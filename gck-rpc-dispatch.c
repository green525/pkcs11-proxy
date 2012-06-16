/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gck-rpc-dispatch.h - receiver of our PKCS#11 protocol.

   Copyright (C) 2008, Stef Walter

   The Gnome Keyring Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The Gnome Keyring Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the Gnome Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.

   Author: Stef Walter <stef@memberwebs.com>
*/

#include "config.h"

#include "gck-rpc-layer.h"
#include "gck-rpc-private.h"

#include "pkcs11/pkcs11.h"
#include "pkcs11/pkcs11g.h"
#include "pkcs11/pkcs11i.h"

#include <sys/types.h>
#include <sys/param.h>
#ifdef __MINGW32__
# include <winsock2.h>
#else
# include <sys/socket.h>
# include <sys/un.h>
# include <arpa/inet.h>
# include <netinet/in.h>
# include <netinet/tcp.h>
#endif
#include <pthread.h>
#include <signal.h>
#include <sys/wait.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <time.h>

/* Where we dispatch the calls to */
static CK_FUNCTION_LIST_PTR pkcs11_module = NULL;

/* The error returned on protocol failures */
#define PARSE_ERROR CKR_DEVICE_ERROR
#define PREP_ERROR  CKR_DEVICE_MEMORY

typedef struct _CallState {
	GckRpcMessage *req;
	GckRpcMessage *resp;
	void *allocated;
	uint32_t msg_id;
	int sock;
	int call;
} CallState;

typedef struct _DispatchState {
	struct _DispatchState *next;
	pid_t pid;
} DispatchState;

/* A linked list of dispatcher threads */
static DispatchState *pkcs11_dispatchers = NULL;

/* -----------------------------------------------------------------------------
 * LOGGING and DEBUGGING
 */
#undef DEBUG_OUTPUT
#define DEBUG_OUTPUT 0
#if DEBUG_OUTPUT
#define debug(x) gck_rpc_debug x
#else
#define debug(x)
#endif

#define warning(x) gck_rpc_warn x

#define return_val_if_fail(x, v) \
	if (!(x)) { rpc_warn ("'%s' not true at %s", #x, __func__); return v; }

void gck_rpc_log(const char *msg, ...)
{
	va_list ap;
	char buf[1024];

	snprintf(buf, sizeof(buf), "%d,%x %s", getpid(), pthread_self(), msg);
	va_start(ap, msg);
	vfprintf(stdout, buf, ap);
	printf("\n");
	va_end(ap);
}

/* -------------------------------------------------------------------------------
 * CALL STRUCTURES
 */

static int call_init(CallState ** cs, int sock)
{
	CallState *new_cs = NULL;
	assert(cs);

	/* Initialize call */
	new_cs = calloc(1, sizeof(CallState));
	if (new_cs == NULL)
		return 0;

	/* Initialize message buffers */
	new_cs->req = gck_rpc_message_new((EggBufferAllocator) realloc);
	new_cs->resp = gck_rpc_message_new((EggBufferAllocator) realloc);
	if (!new_cs->req || !new_cs->resp) {
		gck_rpc_message_free(new_cs->req);
		gck_rpc_message_free(new_cs->resp);
		return 0;
	}

	new_cs->sock = sock;
	new_cs->allocated = NULL;
	*cs = new_cs;
	return 1;
}

static void *call_alloc(CallState * cs, size_t length)
{
	void **data;

	assert(cs);

	if (length > 0x7fffffff)
		return NULL;

	data = malloc(sizeof(void *) + length);
	if (!data)
		return NULL;

	/* Munch up the memory to help catch bugs */
	memset(data, 0xff, sizeof(void *) + length);

	/* Store pointer to next allocated block at beginning */
	*data = cs->allocated;
	cs->allocated = data;

	/* Data starts after first pointer */
	return (void *)(data + 1);
}

static void call_uninit(CallState * cs)
{
	void *allocated;
	void **data;

	assert(cs);

	allocated = cs->allocated;
	while (allocated) {
		data = (void **)allocated;

		/* Pointer to the next allocation */
		allocated = *data;
		free(data);
	}

	gck_rpc_message_free(cs->req);
	gck_rpc_message_free(cs->resp);

	free(cs);
}

/* -------------------------------------------------------------------
 * PROTOCOL CODE
 */

static CK_RV
proto_read_byte_buffer(CallState * cs, CK_BYTE_PTR * buffer,
		       CK_ULONG * n_buffer)
{
	GckRpcMessage *msg;
	uint32_t length;

	assert(cs);
	assert(buffer);
	assert(n_buffer);

	msg = cs->req;

	/* Check that we're supposed to be reading this at this point */
	assert(!msg->signature || gck_rpc_message_verify_part(msg, "fy"));

	/* The number of ulongs there's room for on the other end */
	if (!egg_buffer_get_uint32
	    (&msg->buffer, msg->parsed, &msg->parsed, &length))
		return PARSE_ERROR;

	*n_buffer = length;
	*buffer = NULL;

	/* If set to zero, then they just want the length */
	if (!length)
		return CKR_OK;

	*buffer = call_alloc(cs, length * sizeof(CK_BYTE));
	if (!*buffer)
		return CKR_DEVICE_MEMORY;

	return CKR_OK;
}

static CK_RV
proto_read_byte_array(CallState * cs, CK_BYTE_PTR * array, CK_ULONG * n_array)
{
	GckRpcMessage *msg;
	const unsigned char *data;
	unsigned char valid;
	size_t n_data;

	assert(cs);

	msg = cs->req;

	/* Check that we're supposed to have this at this point */
	assert(!msg->signature || gck_rpc_message_verify_part(msg, "ay"));

	/* Read out the byte which says whether data is present or not */
	if (!egg_buffer_get_byte
	    (&msg->buffer, msg->parsed, &msg->parsed, &valid))
		return PARSE_ERROR;

	if (!valid) {
		*array = NULL;
		*n_array = 0;
		return CKR_OK;
	}

	/* Point our arguments into the buffer */
	if (!egg_buffer_get_byte_array(&msg->buffer, msg->parsed, &msg->parsed,
				       &data, &n_data))
		return PARSE_ERROR;

	*array = (CK_BYTE_PTR) data;
	*n_array = n_data;
	return CKR_OK;
}

static CK_RV
proto_write_byte_array(CallState * cs, CK_BYTE_PTR array, CK_ULONG len,
		       CK_RV ret)
{
	assert(cs);

	/*
	 * When returning an byte array, in many cases we need to pass
	 * an invalid array along with a length, which signifies CKR_BUFFER_TOO_SMALL.
	 */

	switch (ret) {
	case CKR_BUFFER_TOO_SMALL:
		array = NULL;
		/* fall through */
	case CKR_OK:
		break;

		/* Pass all other errors straight through */
	default:
		return ret;
	};

	if (!gck_rpc_message_write_byte_array(cs->resp, array, len))
		return PREP_ERROR;

	return CKR_OK;
}

static CK_RV
proto_read_ulong_buffer(CallState * cs, CK_ULONG_PTR * buffer,
			CK_ULONG * n_buffer)
{
	GckRpcMessage *msg;
	uint32_t length;

	assert(cs);
	assert(buffer);
	assert(n_buffer);

	msg = cs->req;

	/* Check that we're supposed to be reading this at this point */
	assert(!msg->signature || gck_rpc_message_verify_part(msg, "fu"));

	/* The number of ulongs there's room for on the other end */
	if (!egg_buffer_get_uint32
	    (&msg->buffer, msg->parsed, &msg->parsed, &length))
		return PARSE_ERROR;

	*n_buffer = length;
	*buffer = NULL;

	/* If set to zero, then they just want the length */
	if (!length)
		return CKR_OK;

	*buffer = call_alloc(cs, length * sizeof(CK_ULONG));
	if (!*buffer)
		return CKR_DEVICE_MEMORY;

	return CKR_OK;
}

static CK_RV
proto_write_ulong_array(CallState * cs, CK_ULONG_PTR array, CK_ULONG len,
			CK_RV ret)
{
	assert(cs);

	/*
	 * When returning an ulong array, in many cases we need to pass
	 * an invalid array along with a length, which signifies CKR_BUFFER_TOO_SMALL.
	 */

	switch (ret) {
	case CKR_BUFFER_TOO_SMALL:
		array = NULL;
		/* fall through */
	case CKR_OK:
		break;

		/* Pass all other errors straight through */
	default:
		return ret;
	};

	if (!gck_rpc_message_write_ulong_array(cs->resp, array, len))
		return PREP_ERROR;

	return CKR_OK;
}

static CK_RV
proto_read_attribute_buffer(CallState * cs, CK_ATTRIBUTE_PTR * result,
			    CK_ULONG * n_result)
{
	CK_ATTRIBUTE_PTR attrs;
	GckRpcMessage *msg;
	uint32_t n_attrs, i;
	uint32_t value;

	assert(cs);
	assert(result);
	assert(n_result);

	msg = cs->req;

	/* Make sure this is in the rigth order */
	assert(!msg->signature || gck_rpc_message_verify_part(msg, "fA"));

	/* Read the number of attributes */
	if (!egg_buffer_get_uint32
	    (&msg->buffer, msg->parsed, &msg->parsed, &n_attrs))
		return PARSE_ERROR;

	/* Allocate memory for the attribute structures */
	attrs = call_alloc(cs, n_attrs * sizeof(CK_ATTRIBUTE));
	if (!attrs)
		return CKR_DEVICE_MEMORY;

	/* Now go through and fill in each one */
	for (i = 0; i < n_attrs; ++i) {

		/* The attribute type */
		if (!egg_buffer_get_uint32
		    (&msg->buffer, msg->parsed, &msg->parsed, &value))
			return PARSE_ERROR;

		attrs[i].type = value;

		/* The number of bytes to allocate */
		if (!egg_buffer_get_uint32
		    (&msg->buffer, msg->parsed, &msg->parsed, &value))
			return PARSE_ERROR;

		if (value == 0) {
			attrs[i].pValue = NULL;
			attrs[i].ulValueLen = 0;
		} else {
			attrs[i].pValue = call_alloc(cs, value);
			if (!attrs[i].pValue)
				return CKR_DEVICE_MEMORY;
			attrs[i].ulValueLen = value;
		}
	}

	*result = attrs;
	*n_result = n_attrs;
	return CKR_OK;
}

static CK_RV
proto_read_attribute_array(CallState * cs, CK_ATTRIBUTE_PTR * result,
			   CK_ULONG * n_result)
{
	CK_ATTRIBUTE_PTR attrs;
	const unsigned char *data;
	unsigned char valid;
	GckRpcMessage *msg;
	uint32_t n_attrs, i;
	uint32_t value;
	size_t n_data;

	assert(cs);
	assert(result);
	assert(n_result);

	msg = cs->req;

	/* Make sure this is in the rigth order */
	assert(!msg->signature || gck_rpc_message_verify_part(msg, "aA"));

	/* Read the number of attributes */
	if (!egg_buffer_get_uint32
	    (&msg->buffer, msg->parsed, &msg->parsed, &n_attrs))
		return PARSE_ERROR;

	/* Allocate memory for the attribute structures */
	attrs = call_alloc(cs, n_attrs * sizeof(CK_ATTRIBUTE));
	if (!attrs)
		return CKR_DEVICE_MEMORY;

	/* Now go through and fill in each one */
	for (i = 0; i < n_attrs; ++i) {

		/* The attribute type */
		if (!egg_buffer_get_uint32
		    (&msg->buffer, msg->parsed, &msg->parsed, &value))
			return PARSE_ERROR;

		attrs[i].type = value;

		/* Whether this one is valid or not */
		if (!egg_buffer_get_byte
		    (&msg->buffer, msg->parsed, &msg->parsed, &valid))
			return PARSE_ERROR;

		if (valid) {
			if (!egg_buffer_get_uint32
			    (&msg->buffer, msg->parsed, &msg->parsed, &value))
				return PARSE_ERROR;
			if (!egg_buffer_get_byte_array
			    (&msg->buffer, msg->parsed, &msg->parsed, &data,
			     &n_data))
				return PARSE_ERROR;

			if (data != NULL && n_data != value) {
				gck_rpc_warn
				    ("attribute length and data do not match");
				return PARSE_ERROR;
			}

			CK_ULONG a;

			if (value == sizeof (uint64_t) &&
			    value != sizeof (CK_ULONG) &&
			    gck_rpc_has_ulong_parameter(attrs[i].type)) {

				value = sizeof (CK_ULONG);
				a = *(uint64_t *)data;
				*(CK_ULONG *)data = a;
			}
			attrs[i].pValue = (CK_VOID_PTR) data;
			attrs[i].ulValueLen = value;
		} else {
			attrs[i].pValue = NULL;
			attrs[i].ulValueLen = -1;
		}
	}

	*result = attrs;
	*n_result = n_attrs;
	return CKR_OK;
}

static CK_RV
proto_write_attribute_array(CallState * cs, CK_ATTRIBUTE_PTR array,
			    CK_ULONG len, CK_RV ret)
{
	assert(cs);

	/*
	 * When returning an attribute array, certain errors aren't
	 * actually real errors, these are passed through to the other
	 * side along with the attribute array.
	 */

	switch (ret) {
	case CKR_ATTRIBUTE_SENSITIVE:
	case CKR_ATTRIBUTE_TYPE_INVALID:
	case CKR_BUFFER_TOO_SMALL:
	case CKR_OK:
		break;

		/* Pass all other errors straight through */
	default:
		return ret;
	};

	if (!gck_rpc_message_write_attribute_array(cs->resp, array, len) ||
	    !gck_rpc_message_write_ulong(cs->resp, ret))
		return PREP_ERROR;

	return CKR_OK;
}

static CK_RV proto_read_null_string(CallState * cs, CK_UTF8CHAR_PTR * val)
{
	GckRpcMessage *msg;
	const unsigned char *data;
	size_t n_data;

	assert(cs);
	assert(val);

	msg = cs->req;

	/* Check that we're supposed to have this at this point */
	assert(!msg->signature || gck_rpc_message_verify_part(msg, "z"));

	if (!egg_buffer_get_byte_array
	    (&msg->buffer, msg->parsed, &msg->parsed, &data, &n_data))
		return PARSE_ERROR;

	/* Allocate a block of memory for it */
	*val = call_alloc(cs, n_data);
	if (!*val)
		return CKR_DEVICE_MEMORY;

	memcpy(*val, data, n_data);
	(*val)[n_data] = 0;

	return CKR_OK;
}

static CK_RV proto_read_mechanism(CallState * cs, CK_MECHANISM_PTR mech)
{
	GckRpcMessage *msg;
	const unsigned char *data;
	uint32_t value;
	size_t n_data;

	assert(cs);
	assert(mech);

	msg = cs->req;

	/* Make sure this is in the right order */
	assert(!msg->signature || gck_rpc_message_verify_part(msg, "M"));

	/* The mechanism type */
	if (!egg_buffer_get_uint32
	    (&msg->buffer, msg->parsed, &msg->parsed, &value))
		return PARSE_ERROR;

	/* The mechanism data */
	if (!egg_buffer_get_byte_array
	    (&msg->buffer, msg->parsed, &msg->parsed, &data, &n_data))
		return PARSE_ERROR;

	mech->mechanism = value;
	mech->pParameter = (CK_VOID_PTR) data;
	mech->ulParameterLen = n_data;
	return CKR_OK;
}

static CK_RV proto_write_info(CallState * cs, CK_INFO_PTR info)
{
	GckRpcMessage *msg;

	assert(cs);
	assert(info);

	msg = cs->resp;

	if (!gck_rpc_message_write_version(msg, &info->cryptokiVersion) ||
	    !gck_rpc_message_write_space_string(msg, info->manufacturerID, 32)
	    || !gck_rpc_message_write_ulong(msg, info->flags)
	    || !gck_rpc_message_write_space_string(msg,
						   info->libraryDescription, 32)
	    || !gck_rpc_message_write_version(msg, &info->libraryVersion))
		return PREP_ERROR;

	return CKR_OK;
}

static CK_RV proto_write_slot_info(CallState * cs, CK_SLOT_INFO_PTR info)
{
	GckRpcMessage *msg;

	assert(cs);
	assert(info);

	msg = cs->resp;

	if (!gck_rpc_message_write_space_string(msg, info->slotDescription, 64)
	    || !gck_rpc_message_write_space_string(msg, info->manufacturerID,
						   32)
	    || !gck_rpc_message_write_ulong(msg, info->flags)
	    || !gck_rpc_message_write_version(msg, &info->hardwareVersion)
	    || !gck_rpc_message_write_version(msg, &info->firmwareVersion))
		return PREP_ERROR;

	return CKR_OK;
}

static CK_RV proto_write_token_info(CallState * cs, CK_TOKEN_INFO_PTR info)
{
	GckRpcMessage *msg;

	assert(cs);
	assert(info);

	msg = cs->resp;

	if (!gck_rpc_message_write_space_string(msg, info->label, 32) ||
	    !gck_rpc_message_write_space_string(msg, info->manufacturerID, 32)
	    || !gck_rpc_message_write_space_string(msg, info->model, 16)
	    || !gck_rpc_message_write_space_string(msg, info->serialNumber, 16)
	    || !gck_rpc_message_write_ulong(msg, info->flags)
	    || !gck_rpc_message_write_ulong(msg, info->ulMaxSessionCount)
	    || !gck_rpc_message_write_ulong(msg, info->ulSessionCount)
	    || !gck_rpc_message_write_ulong(msg, info->ulMaxRwSessionCount)
	    || !gck_rpc_message_write_ulong(msg, info->ulRwSessionCount)
	    || !gck_rpc_message_write_ulong(msg, info->ulMaxPinLen)
	    || !gck_rpc_message_write_ulong(msg, info->ulMinPinLen)
	    || !gck_rpc_message_write_ulong(msg, info->ulTotalPublicMemory)
	    || !gck_rpc_message_write_ulong(msg, info->ulFreePublicMemory)
	    || !gck_rpc_message_write_ulong(msg, info->ulTotalPrivateMemory)
	    || !gck_rpc_message_write_ulong(msg, info->ulFreePrivateMemory)
	    || !gck_rpc_message_write_version(msg, &info->hardwareVersion)
	    || !gck_rpc_message_write_version(msg, &info->firmwareVersion)
	    || !gck_rpc_message_write_space_string(msg, info->utcTime, 16))
		return PREP_ERROR;

	return CKR_OK;
}

static CK_RV
proto_write_mechanism_info(CallState * cs, CK_MECHANISM_INFO_PTR info)
{
	GckRpcMessage *msg;

	assert(cs);
	assert(info);

	msg = cs->resp;

	if (!gck_rpc_message_write_ulong(msg, info->ulMinKeySize) ||
	    !gck_rpc_message_write_ulong(msg, info->ulMaxKeySize) ||
	    !gck_rpc_message_write_ulong(msg, info->flags))
		return PREP_ERROR;

	return CKR_OK;
}

static CK_RV proto_write_session_info(CallState * cs, CK_SESSION_INFO_PTR info)
{
	GckRpcMessage *msg;

	assert(cs);
	assert(info);

	msg = cs->resp;

	if (!gck_rpc_message_write_ulong(msg, info->slotID) ||
	    !gck_rpc_message_write_ulong(msg, info->state) ||
	    !gck_rpc_message_write_ulong(msg, info->flags) ||
	    !gck_rpc_message_write_ulong(msg, info->ulDeviceError))
		return PREP_ERROR;

	return CKR_OK;
}

/* -------------------------------------------------------------------
 * CALL MACROS
 */

#define BEGIN_CALL(call_id) \
	debug ((#call_id ": enter")); \
	assert (cs); \
	assert (pkcs11_module); \
	{  \
		CK_ ## call_id _func = pkcs11_module-> call_id; \
		CK_RV _ret = CKR_OK; \
		if (!_func) { _ret = CKR_GENERAL_ERROR; goto _cleanup; }

#define PROCESS_CALL(args)\
	assert (gck_rpc_message_is_verified (cs->req)); \
	_ret = _func args

#define END_CALL \
	_cleanup: \
		debug (("ret: %d", _ret)); \
		return _ret; \
	}

#define IN_BYTE(val) \
	if (!gck_rpc_message_read_byte (cs->req, &val)) \
		{ _ret = PARSE_ERROR; goto _cleanup; }

#define IN_ULONG(val) \
	if (!gck_rpc_message_read_ulong (cs->req, &val)) \
		{ _ret = PARSE_ERROR; goto _cleanup; }

#define IN_STRING(val) \
	_ret = proto_read_null_string (cs, &val); \
	if (_ret != CKR_OK) goto _cleanup;

#define IN_BYTE_BUFFER(buffer, buffer_len) \
	_ret = proto_read_byte_buffer (cs, &buffer, &buffer_len); \
	if (_ret != CKR_OK) goto _cleanup;

#define IN_BYTE_ARRAY(buffer, buffer_len) \
	_ret = proto_read_byte_array (cs, &buffer, &buffer_len); \
	if (_ret != CKR_OK) goto _cleanup;

#define IN_ULONG_BUFFER(buffer, buffer_len) \
	_ret = proto_read_ulong_buffer (cs, &buffer, &buffer_len); \
	if (_ret != CKR_OK) goto _cleanup;

#define IN_ATTRIBUTE_BUFFER(buffer, buffer_len) \
	_ret = proto_read_attribute_buffer (cs, &buffer, &buffer_len); \
	if (_ret != CKR_OK) goto _cleanup;

#define IN_ATTRIBUTE_ARRAY(attrs, n_attrs) \
	_ret = proto_read_attribute_array (cs, &attrs, &n_attrs); \
	if (_ret != CKR_OK) goto _cleanup;

#define IN_MECHANISM(mech) \
	_ret = proto_read_mechanism (cs, &mech); \
	if (_ret != CKR_OK) goto _cleanup;

#define OUT_ULONG(val) \
	if (_ret == CKR_OK && !gck_rpc_message_write_ulong (cs->resp, val)) \
		_ret = PREP_ERROR;

#define OUT_BYTE_ARRAY(array, len) \
	/* Note how we filter return codes */ \
	_ret = proto_write_byte_array (cs, array, len, _ret);

#define OUT_ULONG_ARRAY(array, len) \
	/* Note how we filter return codes */ \
	_ret = proto_write_ulong_array (cs, array, len, _ret);

#define OUT_ATTRIBUTE_ARRAY(array, len) \
	/* Note how we filter return codes */ \
	_ret = proto_write_attribute_array (cs, array, len, _ret);

#define OUT_INFO(val) \
	if (_ret == CKR_OK) \
		_ret = proto_write_info (cs, &val);

#define OUT_SLOT_INFO(val) \
	if (_ret == CKR_OK) \
		_ret = proto_write_slot_info (cs, &val);

#define OUT_TOKEN_INFO(val) \
	if (_ret == CKR_OK) \
		_ret = proto_write_token_info (cs, &val);

#define OUT_MECHANISM_INFO(val) \
	if (_ret == CKR_OK) \
		_ret = proto_write_mechanism_info (cs, &val);

#define OUT_SESSION_INFO(val) \
	if (_ret == CKR_OK) \
		_ret = proto_write_session_info (cs, &val);

/* ---------------------------------------------------------------------------
 * DISPATCH SPECIFIC CALLS
 */

static CK_RV rpc_C_Initialize(CallState * cs)
{
	CK_BYTE_PTR handshake;
	CK_ULONG n_handshake;
	CK_RV ret = CKR_OK;

	debug(("C_Initialize: enter"));

	assert(cs);
	assert(pkcs11_module);

	ret = proto_read_byte_array(cs, &handshake, &n_handshake);
	if (ret == CKR_OK) {

		/* Check to make sure the header matches */
		if (n_handshake != GCK_RPC_HANDSHAKE_LEN ||
		    memcmp(handshake, GCK_RPC_HANDSHAKE, n_handshake) != 0) {
			gck_rpc_warn
			    ("invalid handshake received from connecting module");
			ret = CKR_GENERAL_ERROR;
		}

		assert(gck_rpc_message_is_verified(cs->req));
	}

	/*
	 * We don't actually C_Initialize lower layers. It's assumed
	 * that they'll already be initialzied by the code that loaded us.
	 */

	debug(("ret: %d", ret));
	return ret;
}

static CK_RV rpc_C_Finalize(CallState * cs)
{
	BEGIN_CALL(C_Finalize);
	PROCESS_CALL((NULL));
	END_CALL;
}

static CK_RV rpc_C_GetInfo(CallState * cs)
{
	CK_INFO info;

	BEGIN_CALL(C_GetInfo);
	PROCESS_CALL((&info));
	OUT_INFO(info);
	END_CALL;
}

static CK_RV rpc_C_GetSlotList(CallState * cs)
{
	CK_BBOOL token_present;
	CK_SLOT_ID_PTR slot_list;
	CK_ULONG count;

	BEGIN_CALL(C_GetSlotList);
	IN_BYTE(token_present);
	IN_ULONG_BUFFER(slot_list, count);
	PROCESS_CALL((token_present, slot_list, &count));
	OUT_ULONG_ARRAY(slot_list, count);
	END_CALL;
}

static CK_RV rpc_C_GetSlotInfo(CallState * cs)
{
	CK_SLOT_ID slot_id;
	CK_SLOT_INFO info;

	/* Slot id becomes appartment so lower layers can tell clients apart. */

	BEGIN_CALL(C_GetSlotInfo);
	IN_ULONG(slot_id);
	PROCESS_CALL((slot_id, &info));
	OUT_SLOT_INFO(info);
	END_CALL;
}

static CK_RV rpc_C_GetTokenInfo(CallState * cs)
{
	CK_SLOT_ID slot_id;
	CK_TOKEN_INFO info;

	/* Slot id becomes appartment so lower layers can tell clients apart. */

	BEGIN_CALL(C_GetTokenInfo);
	IN_ULONG(slot_id);
	PROCESS_CALL((slot_id, &info));
	OUT_TOKEN_INFO(info);
	END_CALL;
}

static CK_RV rpc_C_GetMechanismList(CallState * cs)
{
	CK_SLOT_ID slot_id;
	CK_MECHANISM_TYPE_PTR mechanism_list;
	CK_ULONG count;

	/* Slot id becomes appartment so lower layers can tell clients apart. */

	BEGIN_CALL(C_GetMechanismList);
	IN_ULONG(slot_id);
	IN_ULONG_BUFFER(mechanism_list, count);
	PROCESS_CALL((slot_id, mechanism_list, &count));
	OUT_ULONG_ARRAY(mechanism_list, count);
	END_CALL;
}

static CK_RV rpc_C_GetMechanismInfo(CallState * cs)
{
	CK_SLOT_ID slot_id;
	CK_MECHANISM_TYPE type;
	CK_MECHANISM_INFO info;

	/* Slot id becomes appartment so lower layers can tell clients apart. */

	BEGIN_CALL(C_GetMechanismInfo);
	IN_ULONG(slot_id);
	IN_ULONG(type);
	PROCESS_CALL((slot_id, type, &info));
	OUT_MECHANISM_INFO(info);
	END_CALL;
}

static CK_RV rpc_C_InitToken(CallState * cs)
{
	CK_SLOT_ID slot_id;
	CK_UTF8CHAR_PTR pin;
	CK_ULONG pin_len;
	CK_UTF8CHAR_PTR label;

	/* Slot id becomes appartment so lower layers can tell clients apart. */

	BEGIN_CALL(C_InitToken);
	IN_ULONG(slot_id);
	IN_BYTE_ARRAY(pin, pin_len);
	IN_STRING(label);
	PROCESS_CALL((slot_id, pin, pin_len, label));
	END_CALL;
}

static CK_RV rpc_C_WaitForSlotEvent(CallState * cs)
{
	CK_FLAGS flags;
	CK_SLOT_ID slot_id;

	/* Get slot id from appartment lower layers use. */

	BEGIN_CALL(C_WaitForSlotEvent);
	IN_ULONG(flags);
	PROCESS_CALL((flags, &slot_id, NULL));
	slot_id = CK_GNOME_APPARTMENT_SLOT(slot_id);
	OUT_ULONG(slot_id);
	END_CALL;
}

static CK_RV rpc_C_OpenSession(CallState * cs)
{
	CK_SLOT_ID slot_id;
	CK_FLAGS flags;
	CK_SESSION_HANDLE session;

	/* Slot id becomes appartment so lower layers can tell clients apart. */

	BEGIN_CALL(C_OpenSession);
	IN_ULONG(slot_id);
	IN_ULONG(flags);
	PROCESS_CALL((slot_id, flags, NULL, NULL, &session));
	OUT_ULONG(session);
	END_CALL;
}

static CK_RV rpc_C_CloseSession(CallState * cs)
{
	CK_SESSION_HANDLE session;

	BEGIN_CALL(C_CloseSession);
	IN_ULONG(session);
	PROCESS_CALL((session));
	END_CALL;
}

static CK_RV rpc_C_CloseAllSessions(CallState * cs)
{
	CK_SLOT_ID slot_id;

	/* Slot id becomes appartment so lower layers can tell clients apart. */

	BEGIN_CALL(C_CloseAllSessions);
	IN_ULONG(slot_id);
	PROCESS_CALL((slot_id));
	END_CALL;
}

static CK_RV rpc_C_GetFunctionStatus(CallState * cs)
{
	CK_SESSION_HANDLE session;

	BEGIN_CALL(C_GetFunctionStatus);
	IN_ULONG(session);
	PROCESS_CALL((session));
	END_CALL;
}

static CK_RV rpc_C_CancelFunction(CallState * cs)
{
	CK_SESSION_HANDLE session;

	BEGIN_CALL(C_CancelFunction);
	IN_ULONG(session);
	PROCESS_CALL((session));
	END_CALL;
}

static CK_RV rpc_C_GetSessionInfo(CallState * cs)
{
	CK_SESSION_HANDLE session;
	CK_SESSION_INFO info;

	/* Get slot id from appartment lower layers use. */

	BEGIN_CALL(C_GetSessionInfo);
	IN_ULONG(session);
	PROCESS_CALL((session, &info));
	info.slotID = CK_GNOME_APPARTMENT_SLOT(info.slotID);
	OUT_SESSION_INFO(info);
	END_CALL;
}

static CK_RV rpc_C_InitPIN(CallState * cs)
{
	CK_SESSION_HANDLE session;
	CK_UTF8CHAR_PTR pin;
	CK_ULONG pin_len;

	BEGIN_CALL(C_InitPIN);
	IN_ULONG(session);
	IN_BYTE_ARRAY(pin, pin_len);
	PROCESS_CALL((session, pin, pin_len));
	END_CALL;
}

static CK_RV rpc_C_SetPIN(CallState * cs)
{
	CK_SESSION_HANDLE session;
	CK_UTF8CHAR_PTR old_pin;
	CK_ULONG old_len;
	CK_UTF8CHAR_PTR new_pin;
	CK_ULONG new_len;

	BEGIN_CALL(C_SetPIN);
	IN_ULONG(session);
	IN_BYTE_ARRAY(old_pin, old_len);
	IN_BYTE_ARRAY(new_pin, new_len);
	PROCESS_CALL((session, old_pin, old_len, new_pin, new_len));
	END_CALL;
}

static CK_RV rpc_C_GetOperationState(CallState * cs)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR operation_state;
	CK_ULONG operation_state_len;

	BEGIN_CALL(C_GetOperationState);
	IN_ULONG(session);
	IN_BYTE_BUFFER(operation_state, operation_state_len);
	PROCESS_CALL((session, operation_state, &operation_state_len));
	OUT_BYTE_ARRAY(operation_state, operation_state_len);
	END_CALL;
}

static CK_RV rpc_C_SetOperationState(CallState * cs)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR operation_state;
	CK_ULONG operation_state_len;
	CK_OBJECT_HANDLE encryption_key;
	CK_OBJECT_HANDLE authentication_key;

	BEGIN_CALL(C_SetOperationState);
	IN_ULONG(session);
	IN_BYTE_ARRAY(operation_state, operation_state_len);
	IN_ULONG(encryption_key);
	IN_ULONG(authentication_key);
	PROCESS_CALL((session, operation_state, operation_state_len,
		      encryption_key, authentication_key));
	END_CALL;
}

static CK_RV rpc_C_Login(CallState * cs)
{
	CK_SESSION_HANDLE session;
	CK_USER_TYPE user_type;
	CK_UTF8CHAR_PTR pin;
	CK_ULONG pin_len;

	BEGIN_CALL(C_Login);
	IN_ULONG(session);
	IN_ULONG(user_type);
	IN_BYTE_ARRAY(pin, pin_len);
	PROCESS_CALL((session, user_type, pin, pin_len));
	END_CALL;
}

static CK_RV rpc_C_Logout(CallState * cs)
{
	CK_SESSION_HANDLE session;

	BEGIN_CALL(C_Logout);
	IN_ULONG(session);
	PROCESS_CALL((session));
	END_CALL;
}

/* -----------------------------------------------------------------------------
 * OBJECT OPERATIONS
 */

static CK_RV rpc_C_CreateObject(CallState * cs)
{
	CK_SESSION_HANDLE session;
	CK_ATTRIBUTE_PTR template;
	CK_ULONG count;
	CK_OBJECT_HANDLE new_object;

	BEGIN_CALL(C_CreateObject);
	IN_ULONG(session);
	IN_ATTRIBUTE_ARRAY(template, count);
	PROCESS_CALL((session, template, count, &new_object));
	OUT_ULONG(new_object);
	END_CALL;
}

static CK_RV rpc_C_CopyObject(CallState * cs)
{
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE object;
	CK_ATTRIBUTE_PTR template;
	CK_ULONG count;
	CK_OBJECT_HANDLE new_object;

	BEGIN_CALL(C_CopyObject);
	IN_ULONG(session);
	IN_ULONG(object);
	IN_ATTRIBUTE_ARRAY(template, count);
	PROCESS_CALL((session, object, template, count, &new_object));
	OUT_ULONG(new_object);
	END_CALL;
}

static CK_RV rpc_C_DestroyObject(CallState * cs)
{
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE object;

	BEGIN_CALL(C_DestroyObject);
	IN_ULONG(session);
	IN_ULONG(object);
	PROCESS_CALL((session, object));
	END_CALL;
}

static CK_RV rpc_C_GetObjectSize(CallState * cs)
{
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE object;
	CK_ULONG size;

	BEGIN_CALL(C_GetObjectSize);
	IN_ULONG(session);
	IN_ULONG(object);
	PROCESS_CALL((session, object, &size));
	OUT_ULONG(size);
	END_CALL;
}

static CK_RV rpc_C_GetAttributeValue(CallState * cs)
{
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE object;
	CK_ATTRIBUTE_PTR template;
	CK_ULONG count;

	BEGIN_CALL(C_GetAttributeValue);
	IN_ULONG(session);
	IN_ULONG(object);
	IN_ATTRIBUTE_BUFFER(template, count);
	PROCESS_CALL((session, object, template, count));
	OUT_ATTRIBUTE_ARRAY(template, count);
	END_CALL;
}

static CK_RV rpc_C_SetAttributeValue(CallState * cs)
{
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE object;
	CK_ATTRIBUTE_PTR template;
	CK_ULONG count;

	BEGIN_CALL(C_SetAttributeValue);
	IN_ULONG(session);
	IN_ULONG(object);
	IN_ATTRIBUTE_ARRAY(template, count);
	PROCESS_CALL((session, object, template, count));
	END_CALL;
}

static CK_RV rpc_C_FindObjectsInit(CallState * cs)
{
	CK_SESSION_HANDLE session;
	CK_ATTRIBUTE_PTR template;
	CK_ULONG count;

	BEGIN_CALL(C_FindObjectsInit);
	IN_ULONG(session);
	IN_ATTRIBUTE_ARRAY(template, count);
	PROCESS_CALL((session, template, count));
	END_CALL;
}

static CK_RV rpc_C_FindObjects(CallState * cs)
{
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE_PTR objects;
	CK_ULONG max_object_count;
	CK_ULONG object_count;

	BEGIN_CALL(C_FindObjects);
	IN_ULONG(session);
	IN_ULONG_BUFFER(objects, max_object_count);
	PROCESS_CALL((session, objects, max_object_count, &object_count));
	OUT_ULONG_ARRAY(objects, object_count);
	END_CALL;
}

static CK_RV rpc_C_FindObjectsFinal(CallState * cs)
{
	CK_SESSION_HANDLE session;

	BEGIN_CALL(C_FindObjectsFinal);
	IN_ULONG(session);
	PROCESS_CALL((session));
	END_CALL;
}

static CK_RV rpc_C_EncryptInit(CallState * cs)
{
	CK_SESSION_HANDLE session;
	CK_MECHANISM mechanism;
	CK_OBJECT_HANDLE key;

	BEGIN_CALL(C_EncryptInit);
	IN_ULONG(session);
	IN_MECHANISM(mechanism);
	IN_ULONG(key);
	PROCESS_CALL((session, &mechanism, key));
	END_CALL;

}

static CK_RV rpc_C_Encrypt(CallState * cs)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR data;
	CK_ULONG data_len;
	CK_BYTE_PTR encrypted_data;
	CK_ULONG encrypted_data_len;

	BEGIN_CALL(C_Encrypt);
	IN_ULONG(session);
	IN_BYTE_ARRAY(data, data_len);
	IN_BYTE_BUFFER(encrypted_data, encrypted_data_len);
	PROCESS_CALL((session, data, data_len, encrypted_data,
		      &encrypted_data_len));
	OUT_BYTE_ARRAY(encrypted_data, encrypted_data_len);
	END_CALL;
}

static CK_RV rpc_C_EncryptUpdate(CallState * cs)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR part;
	CK_ULONG part_len;
	CK_BYTE_PTR encrypted_part;
	CK_ULONG encrypted_part_len;

	BEGIN_CALL(C_EncryptUpdate);
	IN_ULONG(session);
	IN_BYTE_ARRAY(part, part_len);
	IN_BYTE_BUFFER(encrypted_part, encrypted_part_len);
	PROCESS_CALL((session, part, part_len, encrypted_part,
		      &encrypted_part_len));
	OUT_BYTE_ARRAY(encrypted_part, encrypted_part_len);
	END_CALL;
}

static CK_RV rpc_C_EncryptFinal(CallState * cs)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR last_encrypted_part;
	CK_ULONG last_encrypted_part_len;

	BEGIN_CALL(C_EncryptFinal);
	IN_ULONG(session);
	IN_BYTE_BUFFER(last_encrypted_part, last_encrypted_part_len);
	PROCESS_CALL((session, last_encrypted_part, &last_encrypted_part_len));
	OUT_BYTE_ARRAY(last_encrypted_part, last_encrypted_part_len);
	END_CALL;
}

static CK_RV rpc_C_DecryptInit(CallState * cs)
{
	CK_SESSION_HANDLE session;
	CK_MECHANISM mechanism;
	CK_OBJECT_HANDLE key;

	BEGIN_CALL(C_DecryptInit);
	IN_ULONG(session);
	IN_MECHANISM(mechanism);
	IN_ULONG(key);
	PROCESS_CALL((session, &mechanism, key));
	END_CALL;
}

static CK_RV rpc_C_Decrypt(CallState * cs)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR encrypted_data;
	CK_ULONG encrypted_data_len;
	CK_BYTE_PTR data;
	CK_ULONG data_len;

	BEGIN_CALL(C_Decrypt);
	IN_ULONG(session);
	IN_BYTE_ARRAY(encrypted_data, encrypted_data_len);
	IN_BYTE_BUFFER(data, data_len);
	PROCESS_CALL((session, encrypted_data, encrypted_data_len, data,
		      &data_len));
	OUT_BYTE_ARRAY(data, data_len);
	END_CALL;
}

static CK_RV rpc_C_DecryptUpdate(CallState * cs)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR encrypted_part;
	CK_ULONG encrypted_part_len;
	CK_BYTE_PTR part;
	CK_ULONG part_len;

	BEGIN_CALL(C_DecryptUpdate);
	IN_ULONG(session);
	IN_BYTE_ARRAY(encrypted_part, encrypted_part_len);
	IN_BYTE_BUFFER(part, part_len);
	PROCESS_CALL((session, encrypted_part, encrypted_part_len, part,
		      &part_len));
	OUT_BYTE_ARRAY(part, part_len);
	END_CALL;
}

static CK_RV rpc_C_DecryptFinal(CallState * cs)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR last_part;
	CK_ULONG last_part_len;

	BEGIN_CALL(C_DecryptFinal);
	IN_ULONG(session);
	IN_BYTE_BUFFER(last_part, last_part_len);
	PROCESS_CALL((session, last_part, &last_part_len));
	OUT_BYTE_ARRAY(last_part, last_part_len);
	END_CALL;
}

static CK_RV rpc_C_DigestInit(CallState * cs)
{
	CK_SESSION_HANDLE session;
	CK_MECHANISM mechanism;

	BEGIN_CALL(C_DigestInit);
	IN_ULONG(session);
	IN_MECHANISM(mechanism);
	PROCESS_CALL((session, &mechanism));
	END_CALL;
}

static CK_RV rpc_C_Digest(CallState * cs)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR data;
	CK_ULONG data_len;
	CK_BYTE_PTR digest;
	CK_ULONG digest_len;

	BEGIN_CALL(C_Digest);
	IN_ULONG(session);
	IN_BYTE_ARRAY(data, data_len);
	IN_BYTE_BUFFER(digest, digest_len);
	PROCESS_CALL((session, data, data_len, digest, &digest_len));
	OUT_BYTE_ARRAY(digest, digest_len);
	END_CALL;
}

static CK_RV rpc_C_DigestUpdate(CallState * cs)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR part;
	CK_ULONG part_len;

	BEGIN_CALL(C_DigestUpdate);
	IN_ULONG(session);
	IN_BYTE_ARRAY(part, part_len);
	PROCESS_CALL((session, part, part_len));
	END_CALL;
}

static CK_RV rpc_C_DigestKey(CallState * cs)
{
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE key;

	BEGIN_CALL(C_DigestKey);
	IN_ULONG(session);
	IN_ULONG(key);
	PROCESS_CALL((session, key));
	END_CALL;
}

static CK_RV rpc_C_DigestFinal(CallState * cs)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR digest;
	CK_ULONG digest_len;

	BEGIN_CALL(C_DigestFinal);
	IN_ULONG(session);
	IN_BYTE_BUFFER(digest, digest_len);
	PROCESS_CALL((session, digest, &digest_len));
	OUT_BYTE_ARRAY(digest, digest_len);
	END_CALL;
}

static CK_RV rpc_C_SignInit(CallState * cs)
{
	CK_SESSION_HANDLE session;
	CK_MECHANISM mechanism;
	CK_OBJECT_HANDLE key;

	BEGIN_CALL(C_SignInit);
	IN_ULONG(session);
	IN_MECHANISM(mechanism);
	IN_ULONG(key);
	PROCESS_CALL((session, &mechanism, key));
	END_CALL;
}

static CK_RV rpc_C_Sign(CallState * cs)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR part;
	CK_ULONG part_len;
	CK_BYTE_PTR signature;
	CK_ULONG signature_len;

	BEGIN_CALL(C_Sign);
	IN_ULONG(session);
	IN_BYTE_ARRAY(part, part_len);
	IN_BYTE_BUFFER(signature, signature_len);
	PROCESS_CALL((session, part, part_len, signature, &signature_len));
	OUT_BYTE_ARRAY(signature, signature_len);
	END_CALL;

}

static CK_RV rpc_C_SignUpdate(CallState * cs)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR part;
	CK_ULONG part_len;

	BEGIN_CALL(C_SignUpdate);
	IN_ULONG(session);
	IN_BYTE_ARRAY(part, part_len);
	PROCESS_CALL((session, part, part_len));
	END_CALL;
}

static CK_RV rpc_C_SignFinal(CallState * cs)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR signature;
	CK_ULONG signature_len;

	BEGIN_CALL(C_SignFinal);
	IN_ULONG(session);
	IN_BYTE_BUFFER(signature, signature_len);
	PROCESS_CALL((session, signature, &signature_len));
	OUT_BYTE_ARRAY(signature, signature_len);
	END_CALL;
}

static CK_RV rpc_C_SignRecoverInit(CallState * cs)
{
	CK_SESSION_HANDLE session;
	CK_MECHANISM mechanism;
	CK_OBJECT_HANDLE key;

	BEGIN_CALL(C_SignRecoverInit);
	IN_ULONG(session);
	IN_MECHANISM(mechanism);
	IN_ULONG(key);
	PROCESS_CALL((session, &mechanism, key));
	END_CALL;
}

static CK_RV rpc_C_SignRecover(CallState * cs)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR data;
	CK_ULONG data_len;
	CK_BYTE_PTR signature;
	CK_ULONG signature_len;

	BEGIN_CALL(C_SignRecover);
	IN_ULONG(session);
	IN_BYTE_ARRAY(data, data_len);
	IN_BYTE_BUFFER(signature, signature_len);
	PROCESS_CALL((session, data, data_len, signature, &signature_len));
	OUT_BYTE_ARRAY(signature, signature_len);
	END_CALL;
}

static CK_RV rpc_C_VerifyInit(CallState * cs)
{
	CK_SESSION_HANDLE session;
	CK_MECHANISM mechanism;
	CK_OBJECT_HANDLE key;

	BEGIN_CALL(C_VerifyInit);
	IN_ULONG(session);
	IN_MECHANISM(mechanism);
	IN_ULONG(key);
	PROCESS_CALL((session, &mechanism, key));
	END_CALL;
}

static CK_RV rpc_C_Verify(CallState * cs)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR data;
	CK_ULONG data_len;
	CK_BYTE_PTR signature;
	CK_ULONG signature_len;

	BEGIN_CALL(C_Verify);
	IN_ULONG(session);
	IN_BYTE_ARRAY(data, data_len);
	IN_BYTE_ARRAY(signature, signature_len);
	PROCESS_CALL((session, data, data_len, signature, signature_len));
	END_CALL;
}

static CK_RV rpc_C_VerifyUpdate(CallState * cs)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR part;
	CK_ULONG part_len;

	BEGIN_CALL(C_VerifyUpdate);
	IN_ULONG(session);
	IN_BYTE_ARRAY(part, part_len);
	PROCESS_CALL((session, part, part_len));
	END_CALL;
}

static CK_RV rpc_C_VerifyFinal(CallState * cs)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR signature;
	CK_ULONG signature_len;

	BEGIN_CALL(C_VerifyFinal);
	IN_ULONG(session);
	IN_BYTE_ARRAY(signature, signature_len);
	PROCESS_CALL((session, signature, signature_len));
	END_CALL;
}

static CK_RV rpc_C_VerifyRecoverInit(CallState * cs)
{
	CK_SESSION_HANDLE session;
	CK_MECHANISM mechanism;
	CK_OBJECT_HANDLE key;

	BEGIN_CALL(C_VerifyRecoverInit);
	IN_ULONG(session);
	IN_MECHANISM(mechanism);
	IN_ULONG(key);
	PROCESS_CALL((session, &mechanism, key));
	END_CALL;
}

static CK_RV rpc_C_VerifyRecover(CallState * cs)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR signature;
	CK_ULONG signature_len;
	CK_BYTE_PTR data;
	CK_ULONG data_len;

	BEGIN_CALL(C_VerifyRecover);
	IN_ULONG(session);
	IN_BYTE_ARRAY(signature, signature_len);
	IN_BYTE_BUFFER(data, data_len);
	PROCESS_CALL((session, signature, signature_len, data, &data_len));
	OUT_BYTE_ARRAY(data, data_len);
	END_CALL;
}

static CK_RV rpc_C_DigestEncryptUpdate(CallState * cs)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR part;
	CK_ULONG part_len;
	CK_BYTE_PTR encrypted_part;
	CK_ULONG encrypted_part_len;

	BEGIN_CALL(C_DigestEncryptUpdate);
	IN_ULONG(session);
	IN_BYTE_ARRAY(part, part_len);
	IN_BYTE_BUFFER(encrypted_part, encrypted_part_len);
	PROCESS_CALL((session, part, part_len, encrypted_part,
		      &encrypted_part_len));
	OUT_BYTE_ARRAY(encrypted_part, encrypted_part_len);
	END_CALL;
}

static CK_RV rpc_C_DecryptDigestUpdate(CallState * cs)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR encrypted_part;
	CK_ULONG encrypted_part_len;
	CK_BYTE_PTR part;
	CK_ULONG part_len;

	BEGIN_CALL(C_DecryptDigestUpdate);
	IN_ULONG(session);
	IN_BYTE_ARRAY(encrypted_part, encrypted_part_len);
	IN_BYTE_BUFFER(part, part_len);
	PROCESS_CALL((session, encrypted_part, encrypted_part_len, part,
		      &part_len));
	OUT_BYTE_ARRAY(part, part_len);
	END_CALL;
}

static CK_RV rpc_C_SignEncryptUpdate(CallState * cs)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR part;
	CK_ULONG part_len;
	CK_BYTE_PTR encrypted_part;
	CK_ULONG encrypted_part_len;

	BEGIN_CALL(C_SignEncryptUpdate);
	IN_ULONG(session);
	IN_BYTE_ARRAY(part, part_len);
	IN_BYTE_BUFFER(encrypted_part, encrypted_part_len);
	PROCESS_CALL((session, part, part_len, encrypted_part,
		      &encrypted_part_len));
	OUT_BYTE_ARRAY(encrypted_part, encrypted_part_len);
	END_CALL;
}

static CK_RV rpc_C_DecryptVerifyUpdate(CallState * cs)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR encrypted_part;
	CK_ULONG encrypted_part_len;
	CK_BYTE_PTR part;
	CK_ULONG part_len;

	BEGIN_CALL(C_DecryptVerifyUpdate);
	IN_ULONG(session);
	IN_BYTE_ARRAY(encrypted_part, encrypted_part_len);
	IN_BYTE_BUFFER(part, part_len);
	PROCESS_CALL((session, encrypted_part, encrypted_part_len, part,
		      &part_len));
	OUT_BYTE_ARRAY(part, part_len);
	END_CALL;
}

/* -----------------------------------------------------------------------------
 * KEY OPERATIONS
 */

static CK_RV rpc_C_GenerateKey(CallState * cs)
{
	CK_SESSION_HANDLE session;
	CK_MECHANISM mechanism;
	CK_ATTRIBUTE_PTR template;
	CK_ULONG count;
	CK_OBJECT_HANDLE key;

	BEGIN_CALL(C_GenerateKey);
	IN_ULONG(session);
	IN_MECHANISM(mechanism);
	IN_ATTRIBUTE_ARRAY(template, count);
	PROCESS_CALL((session, &mechanism, template, count, &key));
	OUT_ULONG(key);
	END_CALL;
}

static CK_RV rpc_C_GenerateKeyPair(CallState * cs)
{
	CK_SESSION_HANDLE session;
	CK_MECHANISM mechanism;
	CK_ATTRIBUTE_PTR public_key_template;
	CK_ULONG public_key_attribute_count;
	CK_ATTRIBUTE_PTR private_key_template;
	CK_ULONG private_key_attribute_count;
	CK_OBJECT_HANDLE public_key;
	CK_OBJECT_HANDLE private_key;

	BEGIN_CALL(C_GenerateKeyPair);
	IN_ULONG(session);
	IN_MECHANISM(mechanism);
	IN_ATTRIBUTE_ARRAY(public_key_template, public_key_attribute_count);
	IN_ATTRIBUTE_ARRAY(private_key_template, private_key_attribute_count);
	PROCESS_CALL((session, &mechanism, public_key_template,
		      public_key_attribute_count, private_key_template,
		      private_key_attribute_count, &public_key, &private_key));
	OUT_ULONG(public_key);
	OUT_ULONG(private_key);
	END_CALL;

}

static CK_RV rpc_C_WrapKey(CallState * cs)
{
	CK_SESSION_HANDLE session;
	CK_MECHANISM mechanism;
	CK_OBJECT_HANDLE wrapping_key;
	CK_OBJECT_HANDLE key;
	CK_BYTE_PTR wrapped_key;
	CK_ULONG wrapped_key_len;

	BEGIN_CALL(C_WrapKey);
	IN_ULONG(session);
	IN_MECHANISM(mechanism);
	IN_ULONG(wrapping_key);
	IN_ULONG(key);
	IN_BYTE_BUFFER(wrapped_key, wrapped_key_len);
	PROCESS_CALL((session, &mechanism, wrapping_key, key, wrapped_key,
		      &wrapped_key_len));
	OUT_BYTE_ARRAY(wrapped_key, wrapped_key_len);
	END_CALL;
}

static CK_RV rpc_C_UnwrapKey(CallState * cs)
{
	CK_SESSION_HANDLE session;
	CK_MECHANISM mechanism;
	CK_OBJECT_HANDLE unwrapping_key;
	CK_BYTE_PTR wrapped_key;
	CK_ULONG wrapped_key_len;
	CK_ATTRIBUTE_PTR template;
	CK_ULONG attribute_count;
	CK_OBJECT_HANDLE key;

	BEGIN_CALL(C_UnwrapKey);
	IN_ULONG(session);
	IN_MECHANISM(mechanism);
	IN_ULONG(unwrapping_key);
	IN_BYTE_ARRAY(wrapped_key, wrapped_key_len);
	IN_ATTRIBUTE_ARRAY(template, attribute_count);
	PROCESS_CALL((session, &mechanism, unwrapping_key, wrapped_key,
		      wrapped_key_len, template, attribute_count, &key));
	OUT_ULONG(key);
	END_CALL;
}

static CK_RV rpc_C_DeriveKey(CallState * cs)
{
	CK_SESSION_HANDLE session;
	CK_MECHANISM mechanism;
	CK_OBJECT_HANDLE base_key;
	CK_ATTRIBUTE_PTR template;
	CK_ULONG attribute_count;
	CK_OBJECT_HANDLE key;

	BEGIN_CALL(C_DeriveKey);
	IN_ULONG(session);
	IN_MECHANISM(mechanism);
	IN_ULONG(base_key);
	IN_ATTRIBUTE_ARRAY(template, attribute_count);
	PROCESS_CALL((session, &mechanism, base_key, template, attribute_count,
		      &key));
	OUT_ULONG(key);
	END_CALL;
}

static CK_RV rpc_C_SeedRandom(CallState * cs)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR seed;
	CK_ULONG seed_len;

	BEGIN_CALL(C_SeedRandom);
	IN_ULONG(session);
	IN_BYTE_ARRAY(seed, seed_len);
	PROCESS_CALL((session, seed, seed_len));
	END_CALL;
}

static CK_RV rpc_C_GenerateRandom(CallState * cs)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR random_data;
	CK_ULONG random_len;

	BEGIN_CALL(C_GenerateRandom);
	IN_ULONG(session);
	IN_BYTE_BUFFER(random_data, random_len);
	PROCESS_CALL((session, random_data, random_len));
	OUT_BYTE_ARRAY(random_data, random_len);
	END_CALL;
}

/* ---------------------------------------------------------------------------
 * DISPATCH THREAD HANDLING
 */

static int dispatch_call(CallState * cs)
{
	GckRpcMessage *req, *resp;
	CK_RV ret = CKR_OK;

	assert(cs);

	req = cs->req;
	resp = cs->resp;

	/* This should have been checked by the parsing code */
	assert(req->call_id > GCK_RPC_CALL_ERROR);
	assert(req->call_id < GCK_RPC_CALL_MAX);

	/* Prepare a response for the function to fill in */
	if (!gck_rpc_message_prep(resp, req->call_id, GCK_RPC_RESPONSE)) {
		gck_rpc_warn("couldn't prepare message");
		return 0;
	}

	switch (req->call_id) {

#define CASE_CALL(name) \
		case GCK_RPC_CALL_##name: \
			ret = rpc_##name (cs); \
			break;
		CASE_CALL(C_Initialize)
		    CASE_CALL(C_Finalize)
		    CASE_CALL(C_GetInfo)
		    CASE_CALL(C_GetSlotList)
		    CASE_CALL(C_GetSlotInfo)
		    CASE_CALL(C_GetTokenInfo)
		    CASE_CALL(C_GetMechanismList)
		    CASE_CALL(C_GetMechanismInfo)
		    CASE_CALL(C_InitToken)
		    CASE_CALL(C_WaitForSlotEvent)
		    CASE_CALL(C_OpenSession)
		    CASE_CALL(C_CloseSession)
		    CASE_CALL(C_CloseAllSessions)
		    CASE_CALL(C_GetFunctionStatus)
		    CASE_CALL(C_CancelFunction)
		    CASE_CALL(C_GetSessionInfo)
		    CASE_CALL(C_InitPIN)
		    CASE_CALL(C_SetPIN)
		    CASE_CALL(C_GetOperationState)
		    CASE_CALL(C_SetOperationState)
		    CASE_CALL(C_Login)
		    CASE_CALL(C_Logout)
		    CASE_CALL(C_CreateObject)
		    CASE_CALL(C_CopyObject)
		    CASE_CALL(C_DestroyObject)
		    CASE_CALL(C_GetObjectSize)
		    CASE_CALL(C_GetAttributeValue)
		    CASE_CALL(C_SetAttributeValue)
		    CASE_CALL(C_FindObjectsInit)
		    CASE_CALL(C_FindObjects)
		    CASE_CALL(C_FindObjectsFinal)
		    CASE_CALL(C_EncryptInit)
		    CASE_CALL(C_Encrypt)
		    CASE_CALL(C_EncryptUpdate)
		    CASE_CALL(C_EncryptFinal)
		    CASE_CALL(C_DecryptInit)
		    CASE_CALL(C_Decrypt)
		    CASE_CALL(C_DecryptUpdate)
		    CASE_CALL(C_DecryptFinal)
		    CASE_CALL(C_DigestInit)
		    CASE_CALL(C_Digest)
		    CASE_CALL(C_DigestUpdate)
		    CASE_CALL(C_DigestKey)
		    CASE_CALL(C_DigestFinal)
		    CASE_CALL(C_SignInit)
		    CASE_CALL(C_Sign)
		    CASE_CALL(C_SignUpdate)
		    CASE_CALL(C_SignFinal)
		    CASE_CALL(C_SignRecoverInit)
		    CASE_CALL(C_SignRecover)
		    CASE_CALL(C_VerifyInit)
		    CASE_CALL(C_Verify)
		    CASE_CALL(C_VerifyUpdate)
		    CASE_CALL(C_VerifyFinal)
		    CASE_CALL(C_VerifyRecoverInit)
		    CASE_CALL(C_VerifyRecover)
		    CASE_CALL(C_DigestEncryptUpdate)
		    CASE_CALL(C_DecryptDigestUpdate)
		    CASE_CALL(C_SignEncryptUpdate)
		    CASE_CALL(C_DecryptVerifyUpdate)
		    CASE_CALL(C_GenerateKey)
		    CASE_CALL(C_GenerateKeyPair)
		    CASE_CALL(C_WrapKey)
		    CASE_CALL(C_UnwrapKey)
		    CASE_CALL(C_DeriveKey)
		    CASE_CALL(C_SeedRandom)
		    CASE_CALL(C_GenerateRandom)
#undef CASE_CALL
	default:
		/* This should have been caught by the parse code */
		assert(0 && "Unchecked call");
		break;
	};

	if (ret == CKR_OK) {

		/* Parsing errors? */
		if (gck_rpc_message_buffer_error(req)) {
			gck_rpc_warn
			    ("invalid request from module, probably too short");
			ret = PARSE_ERROR;
		}

		/* Out of memory errors? */
		if (gck_rpc_message_buffer_error(resp)) {
			gck_rpc_warn
			    ("out of memory error putting together message");
			ret = PREP_ERROR;
		}
	}

	/* A filled in response */
	if (ret == CKR_OK) {

		/*
		 * Since we're dealing with many many functions above generating
		 * these messages we want to make sure each of them actually
		 * does what it's supposed to.
		 */

		assert(gck_rpc_message_is_verified(resp));
		assert(resp->call_type == GCK_RPC_RESPONSE);
		assert(resp->call_id == req->call_id);
		assert(gck_rpc_calls[resp->call_id].response);
		assert(strcmp(gck_rpc_calls[resp->call_id].response,
			      resp->signature) == 0);

		/* Fill in an error respnose */
	} else {
		if (!gck_rpc_message_prep
		    (resp, GCK_RPC_CALL_ERROR, GCK_RPC_RESPONSE)
		    || !gck_rpc_message_write_ulong(resp, (uint32_t) ret)
		    || gck_rpc_message_buffer_error(resp)) {
			gck_rpc_warn("out of memory responding with error");
			return 0;
		}
	}

	return 1;
}

static int read_all(int sock, unsigned char *data, size_t len)
{
	int r;

	assert(sock >= 0);
	assert(data);
	assert(len > 0);

	while (len > 0) {

        r = recv(sock, (void *)data, len, 0);

		if (r == 0) {
			/* Connection was closed on client */
			return 0;
		} else if (r == -1) {
			if (errno != EAGAIN && errno != EINTR) {
				gck_rpc_warn("couldn't receive data: %s",
					     strerror(errno));
				return r;
			}
		} else {
			data += r;
			len -= r;
		}
	}
	return 1;
}

static int write_all(int sock, unsigned char *data, size_t len)
{
	int r;

	assert(sock >= 0);
	assert(data);
	assert(len > 0);

	while (len > 0) {

                r = send(sock, (void *)data, len, 0);

		if (r == -1) {
			if (errno == EPIPE) {
				/* Connection closed from client */
				return 0;
			} else if (errno != EAGAIN && errno != EINTR) {
				gck_rpc_warn("couldn't send data: %s",
					     strerror(errno));
				return 0;
			}
		} else {
			data += r;
			len -= r;
		}
	}

	return 1;
}

/* Call state, protecting mutex and conditions */
static CallState *job_cs = NULL;
static pthread_mutex_t job_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t write_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t job_posted = PTHREAD_COND_INITIALIZER;
static pthread_cond_t job_taken = PTHREAD_COND_INITIALIZER;
static pthread_cond_t thread_started = PTHREAD_COND_INITIALIZER;
int max_workers_waiting = 2;
static int workers_waiting = 0;
static int workers_running = 0;
#define THREAD_TIMEOUT 5;

/* worker thread handling incoming messages */
static void * worker_thread(void * t)
{
	unsigned char buf[8];
	CallState *cs = NULL;
	int ret;

	/* initially get the mutex and signal availability */
	ret = pthread_mutex_lock(&job_mutex);
	if (ret != 0) {
		gck_rpc_warn("Worker cannot acquire the mutex: %d", ret);
		pthread_exit(&ret);
	}
	workers_running++;
	pthread_cond_signal(&thread_started);

	/* main loop */
	while (TRUE) {
		workers_waiting++;

		/* wait for a job to become available */
		while (job_cs == NULL)
			pthread_cond_wait(&job_posted, &job_mutex);
		workers_waiting--;

		/* catch the job */
		debug(("Worker received new job"));
		cs = job_cs;
		job_cs = NULL;

		/* signal free space */
		pthread_cond_signal(&job_taken);
		pthread_mutex_unlock(&job_mutex);

		/* ... send for processing ... */
		dispatch_call(cs);

		/* .. send back response length, and then response data */
		egg_buffer_encode_uint32(buf, cs->msg_id);
		egg_buffer_encode_uint32(buf+4, cs->resp->buffer.len);
		ret = pthread_mutex_lock(&write_mutex);
		if (ret != 0) {
			gck_rpc_warn("Worker cannot acquire write permission: %d", ret);
			call_uninit(cs);
			break;
		}
		ret = write_all(cs->sock, buf, 8);
		if (ret)
			ret = write_all(cs->sock, cs->resp->buffer.buf, cs->resp->buffer.len);
		pthread_mutex_unlock(&write_mutex);

		call_uninit(cs);

		/* If there was a write error, the connection was closed */
		if (!ret) {
			gck_rpc_warn("Worker cannot not send response");
			break;
		}

		/* get mutex to signal availability */
		ret = pthread_mutex_lock(&job_mutex);
		if (ret != 0) {
			gck_rpc_warn("Worker cannot acquire the mutex: %d", ret);
			break;
		}

		/* Exit if there are too many waiting workers */
		if (workers_waiting > max_workers_waiting) {
			pthread_mutex_unlock(&job_mutex);
			debug(("Too many idle worker threads, exiting"));
			break;
		}
	}

	/* de-register from running workers */
	pthread_mutex_lock(&job_mutex);
	workers_running--;
	pthread_mutex_unlock(&job_mutex);

	pthread_exit(&ret);
}

static void run_dispatch_loop(int sock)
{
	unsigned char buf[8];
	CallState *cs = NULL;
	uint32_t len;
	uint64_t appid;
	CK_C_INITIALIZE_ARGS p11_init_args;
	CK_RV rv;
	int ret;
	pthread_t tid;
	struct timespec timeout;

	assert(sock != -1);

	/* The client application */
	if (read_all(sock, (unsigned char *)&appid, sizeof (appid)) <= 0) {
		gck_rpc_warn("Can't read appid\n");
		exit(1);
	}
	gck_rpc_log("New session %08x-%08x\n", (uint32_t) (appid >> 32),
		    (uint32_t) appid);

	/* TODO: register SIGTERM handler */

	/* RPC layer expects initialized module */
	memset(&p11_init_args, 0, sizeof(p11_init_args));
	p11_init_args.flags = CKF_OS_LOCKING_OK;
	rv = (pkcs11_module->C_Initialize) (&p11_init_args);
	if (rv != CKR_OK) {
		gck_rpc_warn("could not initialize PKCS#11 module: 0x08x", (int)rv);
		exit(1);
	}

	/* The main thread loop */
	while (TRUE) {
		/* Setup a new call */
		if (!call_init(&cs, sock)) {
			gck_rpc_warn("out of memory");
			break;
		}

		/* Read the message ID and number of bytes ... */
		ret = read_all(sock, buf, 8);
		if (ret == 0) {
			gck_rpc_log("dispatcher connection closed");
			break;
		} else if (ret < 0)
			break;

		/* Random message ID */
		cs->msg_id = egg_buffer_decode_uint32(buf);

		/* Calculate the number of bytes */
		len = egg_buffer_decode_uint32(buf+4);
		if (len >= 0x0FFFFFFF) {
			gck_rpc_warn
			    ("invalid message size from module: %u bytes", len);
			break;
		}
		debug(("Received message id: %08x, len: %d", cs->msg_id, len));

		/* Allocate memory */
		egg_buffer_reserve(&cs->req->buffer, cs->req->buffer.len + len);
		if (egg_buffer_has_error(&cs->req->buffer)) {
			gck_rpc_warn("error allocating buffer for message");
			break;
		}

		/* ... and read/parse in the actual message */
		if (read_all(sock, cs->req->buffer.buf, len) <= 0) {
			gck_rpc_warn("dispatcher read error");
			break;
		}

		egg_buffer_add_empty(&cs->req->buffer, len);

		if (!gck_rpc_message_parse(cs->req, GCK_RPC_REQUEST))
			break;

		ret = pthread_mutex_lock(&job_mutex);
		if (ret != 0) {
			gck_rpc_warn("Dispatcher cannot acquire mutex: %d", ret);
			break;
		}

		/* If there is no worker thread available, create a new one and
		 * wait for its availability
		 */
		if (workers_waiting == 0) {
			ret = pthread_create(&tid, NULL, worker_thread, NULL);
			if (ret != 0) {
				gck_rpc_warn("Could not start new worker thread: %d", ret);
				break;
			}
			clock_gettime(CLOCK_REALTIME, &timeout);
			timeout.tv_sec += THREAD_TIMEOUT;
			ret = pthread_cond_timedwait(&thread_started, &job_mutex, &timeout);
			if (ret == 0)
				debug(("New worker thread created: 0x%x", tid));
			else if (workers_waiting == 0) {
				gck_rpc_warn("No worker thread available nor startable: %d", ret);
				pthread_mutex_unlock(&job_mutex);
				break;
			}
		}

		/* post the job */
		job_cs = cs;

		/* signal job available and wait for it being taken */
		while (job_cs != NULL) {
			pthread_cond_signal(&job_posted);
			pthread_cond_wait(&job_taken, &job_mutex);
		}

		pthread_mutex_unlock(&job_mutex);
		gck_rpc_log("running: %d, waiting: %d", workers_running, workers_waiting);
	}

	/* De-initialize the PKCS#11 module */
	(pkcs11_module->C_Finalize) (NULL);

	/* Close the connection */
	close(sock);

	exit(0);
}

/* ---------------------------------------------------------------------------
 * MAIN PROCESS
 */

/* The main daemon socket that we're listening on */
static int pkcs11_socket = -1;

/* The unix socket path, that we listen on */
static char pkcs11_socket_path[MAXPATHLEN] = { 0, };

void gck_rpc_layer_accept(void)
{
	struct sockaddr_un addr;
	pid_t new_pid;
	socklen_t addrlen;
	int new_fd;

	assert(pkcs11_socket != -1);

	addrlen = sizeof(addr);
	new_fd = accept(pkcs11_socket, (struct sockaddr *)&addr, &addrlen);
	if (new_fd < 0) {
		gck_rpc_warn("cannot accept pkcs11 connection: %s",
			     strerror(errno));
		return;
	}

	/* fork new child to handle connection */
	new_pid = fork();
	if (new_pid < 0) {
		gck_rpc_warn("cannot fork new process: %d", new_pid);
		close(new_fd);
	} else if (new_pid > 0) {
		debug(("forked new child process: %d", new_pid));
		close(new_fd);
	} else {
		debug(("ready to handle connection"));
		close(pkcs11_socket);
		run_dispatch_loop(new_fd);
	}
}

int gck_rpc_layer_initialize(const char *prefix, CK_FUNCTION_LIST_PTR module)
{
	struct sockaddr_un addr;
	int sock;

#ifdef _DEBUG
	GCK_RPC_CHECK_CALLS();
#endif

	assert(module);
	assert(prefix);

	/* cannot be called more than once */
	assert(!pkcs11_module);
	assert(pkcs11_socket == -1);
	assert(pkcs11_dispatchers == NULL);

	memset(&addr, 0, sizeof(addr));

#ifdef  __MINGW32__
        {
		WSADATA wsaData;
		int iResult;

		iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
		if (iResult != 0) {
			gck_rpc_warn("WSAStartup failed: %d\n", iResult);
			return -1;
		}
        }
#endif

	if (!strncmp("tcp://", prefix, 6)) {
		int one = 1, port;
		char *p = NULL;
		const char *ip;

		ip = strdup(prefix + 6);
		if (ip)
			p = strchr(ip, ':');

		if (!ip) {
			gck_rpc_warn("invalid syntax for pkcs11 socket : %s",
				     prefix);
			return -1;
		}

		if (p) {
			*p = '\0';
			port = strtol(p + 1, NULL, 0);
		} else
			port = 0;

		sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

		if (sock < 0) {
			gck_rpc_warn("couldn't create pkcs11 socket: %s",
				     strerror(errno));
			return -1;
		}

                if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY,
                               (char *)&one, sizeof (one)) == -1) {
                        gck_rpc_warn("couldn't create set pkcs11 "
				 "socket options : %s", strerror (errno));
                        return -1;
                }

		if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
                               (char *)&one, sizeof(one)) == -1) {
			gck_rpc_warn
			    ("couldn't create set pkcs11 socket options : %s",
			     strerror(errno));
			return -1;
		}

		addr.sun_family = AF_INET;
		if (inet_aton(ip, &((struct sockaddr_in *)&addr)->sin_addr) ==
		    0) {
			gck_rpc_warn("bad inet address : %s", ip);
			return -1;
		}
		((struct sockaddr_in *)&addr)->sin_port = htons(port);

		snprintf(pkcs11_socket_path, sizeof(pkcs11_socket_path),
			 "%s", prefix);
	} else {
		snprintf(pkcs11_socket_path, sizeof(pkcs11_socket_path),
			 "%s/socket.pkcs11", prefix);

		sock = socket(AF_UNIX, SOCK_STREAM, 0);

		if (sock < 0) {
			gck_rpc_warn("couldn't create pkcs11 socket: %s",
				     strerror(errno));
			return -1;
		}

		addr.sun_family = AF_UNIX;
		unlink(pkcs11_socket_path);
		strncpy(addr.sun_path, pkcs11_socket_path,
			sizeof(addr.sun_path));
	}

	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		gck_rpc_warn("couldn't bind to pkcs11 socket: %s: %s",
			     pkcs11_socket_path, strerror(errno));
		return -1;
	}

	if (listen(sock, 128) < 0) {
		gck_rpc_warn("couldn't listen on pkcs11 socket: %s: %s",
			     pkcs11_socket_path, strerror(errno));
		return -1;
	}

	if (!strncmp("tcp://", prefix, 6)) {
		struct sockaddr_in sa;
		socklen_t sa_len;

		sa_len = sizeof(sa);

		if (getsockname(sock, (struct sockaddr *)&sa, &sa_len) == -1) {
			gck_rpc_warn("getsockname failed on pkcs11 socket: %s: %s",
				     pkcs11_socket_path, strerror(errno));
			return -1;
		}

		snprintf(pkcs11_socket_path, sizeof(pkcs11_socket_path),
			 "%s:%d", inet_ntoa(sa.sin_addr), ntohs(sa.sin_port));
	}

	gck_rpc_log("Listening on: %s\n", pkcs11_socket_path);

	pkcs11_module = module;
	pkcs11_socket = sock;
	pkcs11_dispatchers = NULL;

	return sock;
}

void gck_rpc_layer_uninitialize(void)
{
	DispatchState *ds, *next;
	int status;

	if (!pkcs11_module)
		return;

	/* Close our main listening socket */
	if (pkcs11_socket != -1)
		close(pkcs11_socket);
	pkcs11_socket = -1;

	/* Delete our unix socket */
	if (pkcs11_socket_path[0])
		unlink(pkcs11_socket_path);
	pkcs11_socket_path[0] = 0;

	/* Stop all of the dispatch children */
	for (ds = pkcs11_dispatchers; ds; ds = next) {
		next = ds->next;

		kill(ds->pid, SIGTERM);
		waitpid(ds->pid, &status, 0);

		free(ds);
	}

	pkcs11_module = NULL;
}
