#include <tcl.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#ifdef _WIN32
#  include <windows.h>
#  include <bcrypt.h>
#else
#  include <sys/random.h>
#  include <errno.h>
#endif

#include <mbedtls/gcm.h>

#include "omemo.h"

#ifndef PACKAGE_VERSION
#define PACKAGE_VERSION "0.3.0"
#endif

#define OMEMO_PROTO_VERSION "0.3"

static Tcl_Obj    *g_load_cmd  = NULL;
static Tcl_Obj    *g_store_cmd = NULL;
static Tcl_Interp *g_interp    = NULL;
static int         g_cb_err    = 0;

static void SecureZero(void *p, size_t n) {
    volatile uint8_t *vp = (volatile uint8_t *)p;
    while (n--) *vp++ = 0;
}

struct ErrMap { int rc; const char *tag; };
static const struct ErrMap g_errs[] = {
    { OMEMO_EPROTOBUF, "EPROTOBUF" },
    { OMEMO_ECRYPTO,   "ECRYPTO"   },
    { OMEMO_ECORRUPT,  "ECORRUPT"  },
    { OMEMO_EPARAM,    "EPARAM"    },
    { OMEMO_ESTATE,    "ESTATE"    },
    { OMEMO_EKEYGONE,  "EKEYGONE"  },
    { OMEMO_ESTORE,    "ESTORE"    },
    { OMEMO_EUSER,     "EUSER"     },
};

static int SetOmemoError(Tcl_Interp *ip, int rc) {
    const char *tag = "EUNKNOWN";
    for (size_t i = 0; i < sizeof(g_errs)/sizeof(g_errs[0]); ++i) {
        if (g_errs[i].rc == rc) { tag = g_errs[i].tag; break; }
    }
    int callback_origin = (rc == OMEMO_EUSER && g_cb_err);
    if (callback_origin) {
        tag = "ESTORAGE";
        g_cb_err = 0;
    } else {
        Tcl_SetObjResult(ip, Tcl_ObjPrintf("omemo: %s (rc=%d)", tag, rc));
    }
    Tcl_Obj *code = Tcl_NewListObj(0, NULL);
    Tcl_ListObjAppendElement(NULL, code, Tcl_NewStringObj("OMEMO", -1));
    Tcl_ListObjAppendElement(NULL, code, Tcl_NewStringObj(tag, -1));
    Tcl_SetObjErrorCode(ip, code);
    return TCL_ERROR;
}

typedef struct PicoStore {
    struct omemoStore base;
    uint32_t    device_id;
    Tcl_Command cmd;
} PicoStore;

typedef struct PicoSession {
    struct omemoSession base;
    char       *jid;
    uint32_t    device_id;
    Tcl_Command cmd;
} PicoSession;

static int StoreSubCmd(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]);
static int SessionSubCmd(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]);

static void StoreDeleteProc(ClientData cd) {
    PicoStore *ps = (PicoStore *)cd;
    SecureZero(&ps->base, sizeof(ps->base));
    Tcl_Free(ps);
}

static void SessionDeleteProc(ClientData cd) {
    PicoSession *ps = (PicoSession *)cd;
    SecureZero(&ps->base, sizeof(ps->base));
    if (ps->jid) {
        SecureZero(ps->jid, strlen(ps->jid));
        Tcl_Free(ps->jid);
    }
    Tcl_Free(ps);
}

static PicoStore *LookupStore(Tcl_Interp *ip, Tcl_Obj *nameObj) {
    Tcl_CmdInfo info;
    if (!Tcl_GetCommandInfo(ip, Tcl_GetString(nameObj), &info) ||
        info.objProc != StoreSubCmd) {
        Tcl_SetObjResult(ip, Tcl_ObjPrintf("no such omemo store: %s",
                                            Tcl_GetString(nameObj)));
        return NULL;
    }
    return (PicoStore *)info.objClientData;
}

static int CheckBytes(Tcl_Interp *ip, Tcl_Obj *obj, Tcl_Size expected,
                      const char *what, unsigned char **out, Tcl_Size *outn) {
    Tcl_Size n = 0;
    unsigned char *p = Tcl_GetByteArrayFromObj(obj, &n);
    if (expected >= 0 && n != expected) {
        Tcl_SetObjResult(ip, Tcl_ObjPrintf("%s must be %ld bytes, got %ld",
                                            what, (long)expected, (long)n));
        Tcl_SetErrorCode(ip, "OMEMO", "EPARAM", NULL);
        return TCL_ERROR;
    }
    *out = p;
    if (outn) *outn = n;
    return TCL_OK;
}

static int OmemoVersionCmd(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    (void)cd; (void)objv;
    if (objc != 1) { Tcl_WrongNumArgs(ip, 1, objv, NULL); return TCL_ERROR; }
    Tcl_SetObjResult(ip, Tcl_NewStringObj(OMEMO_PROTO_VERSION, -1));
    return TCL_OK;
}

static int OmemoRandomCmd(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 2) { Tcl_WrongNumArgs(ip, 1, objv, "nbytes"); return TCL_ERROR; }
    int n = 0;
    if (Tcl_GetIntFromObj(ip, objv[1], &n) != TCL_OK) return TCL_ERROR;
    if (n <= 0 || n > 4096) {
        Tcl_SetObjResult(ip, Tcl_NewStringObj("nbytes must be 1..4096", -1));
        return TCL_ERROR;
    }
    Tcl_Obj *res = Tcl_NewByteArrayObj(NULL, n);
    unsigned char *buf = Tcl_GetByteArrayFromObj(res, NULL);
    if (omemoRandom(buf, (size_t)n) != 0) {
        Tcl_DecrRefCount(res);
        Tcl_SetObjResult(ip, Tcl_NewStringObj("rng failed", -1));
        return TCL_ERROR;
    }
    Tcl_SetObjResult(ip, res);
    return TCL_OK;
}

static int OmemoFingerprintCmd(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 2) { Tcl_WrongNumArgs(ip, 1, objv, "ik_bytes"); return TCL_ERROR; }
    unsigned char *ik = NULL;
    Tcl_Size n = 0;
    if (CheckBytes(ip, objv[1], 32, "ik_bytes", &ik, &n) != TCL_OK) return TCL_ERROR;
    static const char hex[] = "0123456789abcdef";
    char out[64 + 7 + 1];
    int w = 0;
    for (int i = 0; i < 32; ++i) {
        out[w++] = hex[(ik[i] >> 4) & 0xf];
        out[w++] = hex[ik[i] & 0xf];
        if ((i % 4) == 3 && i != 31) out[w++] = ' ';
    }
    out[w] = '\0';
    Tcl_SetObjResult(ip, Tcl_NewStringObj(out, w));
    return TCL_OK;
}

static int OmemoSetStorageCmd(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    Tcl_Obj *loadObj = NULL, *storeObj = NULL;
    if (objc != 5) {
        Tcl_WrongNumArgs(ip, 1, objv, "-load cmd -store cmd");
        return TCL_ERROR;
    }
    for (int i = 1; i < objc; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-load") == 0)       loadObj = objv[i+1];
        else if (strcmp(opt, "-store") == 0) storeObj = objv[i+1];
        else {
            Tcl_SetObjResult(ip, Tcl_ObjPrintf("unknown option: %s", opt));
            return TCL_ERROR;
        }
    }
    if (!loadObj || !storeObj) {
        Tcl_SetObjResult(ip, Tcl_NewStringObj("both -load and -store are required", -1));
        return TCL_ERROR;
    }
    Tcl_IncrRefCount(loadObj);
    Tcl_IncrRefCount(storeObj);
    if (g_load_cmd)  Tcl_DecrRefCount(g_load_cmd);
    if (g_store_cmd) Tcl_DecrRefCount(g_store_cmd);
    g_load_cmd  = loadObj;
    g_store_cmd = storeObj;
    g_interp    = ip;
    return TCL_OK;
}

static int OmemoEncryptMessageCmd(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 2) { Tcl_WrongNumArgs(ip, 1, objv, "plaintext"); return TCL_ERROR; }
    Tcl_Size n = 0;
    unsigned char *plain = Tcl_GetByteArrayFromObj(objv[1], &n);
    Tcl_Obj *ctObj  = Tcl_NewByteArrayObj(NULL, n);
    unsigned char *ct = Tcl_SetByteArrayLength(ctObj, n);
    uint8_t key[32];
    uint8_t iv[12];
    int rc = omemoEncryptMessage(ct, key, iv, plain, (size_t)n);
    if (rc != 0) { Tcl_DecrRefCount(ctObj); return SetOmemoError(ip, rc); }
    Tcl_Obj *result = Tcl_NewDictObj();
    Tcl_DictObjPut(NULL, result, Tcl_NewStringObj("ct",  2), ctObj);
    Tcl_DictObjPut(NULL, result, Tcl_NewStringObj("key", 3), Tcl_NewByteArrayObj(key, 32));
    Tcl_DictObjPut(NULL, result, Tcl_NewStringObj("iv",  2), Tcl_NewByteArrayObj(iv, 12));
    SecureZero(key, sizeof(key));
    SecureZero(iv,  sizeof(iv));
    Tcl_SetObjResult(ip, result);
    return TCL_OK;
}

static int OmemoDecryptMessageCmd(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 4) { Tcl_WrongNumArgs(ip, 1, objv, "key iv ct"); return TCL_ERROR; }
    Tcl_Size keyn = 0, ivn = 0, ctn = 0;
    unsigned char *key = Tcl_GetByteArrayFromObj(objv[1], &keyn);
    unsigned char *iv  = Tcl_GetByteArrayFromObj(objv[2], &ivn);
    unsigned char *ct  = Tcl_GetByteArrayFromObj(objv[3], &ctn);
    if (ivn != 12) {
        Tcl_SetObjResult(ip, Tcl_NewStringObj("iv must be 12 bytes", -1));
        Tcl_SetErrorCode(ip, "OMEMO", "EPARAM", NULL);
        return TCL_ERROR;
    }
    if (keyn < 32) {
        Tcl_SetObjResult(ip, Tcl_NewStringObj("key must be at least 32 bytes", -1));
        Tcl_SetErrorCode(ip, "OMEMO", "EPARAM", NULL);
        return TCL_ERROR;
    }
    Tcl_Obj *outObj = Tcl_NewByteArrayObj(NULL, ctn);
    unsigned char *out = Tcl_SetByteArrayLength(outObj, ctn);
    int rc = omemoDecryptMessage(out, key, (size_t)keyn, iv, ct, (size_t)ctn);
    if (rc != 0) { Tcl_DecrRefCount(outObj); return SetOmemoError(ip, rc); }
    Tcl_SetObjResult(ip, outObj);
    return TCL_OK;
}

/* ::omemo::media_encrypt plaintext -> dict {ct <ciphertext||16-tag> key <32> iv <12>}
 * AES-256-GCM for XEP-0454 media sharing: fresh key+iv, tag appended to ct. */
static int MediaEncryptCmd(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 2) { Tcl_WrongNumArgs(ip, 1, objv, "plaintext"); return TCL_ERROR; }
    Tcl_Size n = 0;
    unsigned char *plain = Tcl_GetByteArrayFromObj(objv[1], &n);
    uint8_t key[32];
    uint8_t iv[12];
    int r = omemoRandom(key, 32);
    if (!r) r = omemoRandom(iv, 12);
    Tcl_Obj *ctObj = Tcl_NewByteArrayObj(NULL, n + 16);
    unsigned char *ct = Tcl_SetByteArrayLength(ctObj, n + 16);
    mbedtls_gcm_context g;
    mbedtls_gcm_init(&g);
    if (!r) r = mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (!r) r = mbedtls_gcm_crypt_and_tag(&g, MBEDTLS_GCM_ENCRYPT, (size_t)n, iv, 12,
                                          (const unsigned char *)"", 0, plain, ct, 16, ct + n);
    mbedtls_gcm_free(&g);
    if (r) {
        SecureZero(key, sizeof(key));
        SecureZero(iv,  sizeof(iv));
        Tcl_DecrRefCount(ctObj);
        return SetOmemoError(ip, OMEMO_ECRYPTO);
    }
    Tcl_Obj *result = Tcl_NewDictObj();
    Tcl_DictObjPut(NULL, result, Tcl_NewStringObj("ct",  2), ctObj);
    Tcl_DictObjPut(NULL, result, Tcl_NewStringObj("key", 3), Tcl_NewByteArrayObj(key, 32));
    Tcl_DictObjPut(NULL, result, Tcl_NewStringObj("iv",  2), Tcl_NewByteArrayObj(iv, 12));
    SecureZero(key, sizeof(key));
    SecureZero(iv,  sizeof(iv));
    Tcl_SetObjResult(ip, result);
    return TCL_OK;
}

/* ::omemo::media_decrypt key iv ct -> plaintext  (ct = ciphertext||16-tag)
 * key must be 32 bytes; iv length taken from the byte array (some senders use
 * 16); ct must be at least 16 bytes. */
static int MediaDecryptCmd(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc != 4) { Tcl_WrongNumArgs(ip, 1, objv, "key iv ct"); return TCL_ERROR; }
    Tcl_Size keyn = 0, ivn = 0, ctn = 0;
    unsigned char *key = Tcl_GetByteArrayFromObj(objv[1], &keyn);
    unsigned char *iv  = Tcl_GetByteArrayFromObj(objv[2], &ivn);
    unsigned char *ct  = Tcl_GetByteArrayFromObj(objv[3], &ctn);
    if (keyn != 32 || ctn < 16) return SetOmemoError(ip, OMEMO_EPARAM);
    Tcl_Size plen = ctn - 16;
    Tcl_Obj *outObj = Tcl_NewByteArrayObj(NULL, plen);
    unsigned char *out = Tcl_SetByteArrayLength(outObj, plen);
    mbedtls_gcm_context g;
    mbedtls_gcm_init(&g);
    int r = mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (!r) r = mbedtls_gcm_auth_decrypt(&g, (size_t)plen, iv, (size_t)ivn,
                                         (const unsigned char *)"", 0,
                                         ct + plen, 16, ct, out);
    mbedtls_gcm_free(&g);
    if (r) { Tcl_DecrRefCount(outObj); return SetOmemoError(ip, OMEMO_ECRYPTO); }
    Tcl_SetObjResult(ip, outObj);
    return TCL_OK;
}

static int ParseDevice(Tcl_Interp *ip, Tcl_Obj *obj, uint32_t *out) {
    Tcl_WideInt w = 0;
    if (Tcl_GetWideIntFromObj(ip, obj, &w) != TCL_OK) return TCL_ERROR;
    if (w < 0 || w > 0xffffffffLL) {
        Tcl_SetObjResult(ip, Tcl_NewStringObj("device must fit in uint32", -1));
        Tcl_SetErrorCode(ip, "OMEMO", "EPARAM", NULL);
        return TCL_ERROR;
    }
    *out = (uint32_t)w;
    return TCL_OK;
}

static int StoreCreate(Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    /* objv: omemo::store create <name> -device <uint32> */
    if (objc != 5) {
        Tcl_WrongNumArgs(ip, 2, objv, "name -device uint32");
        return TCL_ERROR;
    }
    const char *name = Tcl_GetString(objv[2]);
    if (strcmp(Tcl_GetString(objv[3]), "-device") != 0) {
        Tcl_SetObjResult(ip, Tcl_NewStringObj("expected -device", -1));
        return TCL_ERROR;
    }
    uint32_t dev = 0;
    if (ParseDevice(ip, objv[4], &dev) != TCL_OK) return TCL_ERROR;
    PicoStore *ps = (PicoStore *)Tcl_Alloc(sizeof(*ps));
    memset(ps, 0, sizeof(*ps));
    ps->device_id = dev;
    ps->cmd = Tcl_CreateObjCommand(ip, name, StoreSubCmd, ps, StoreDeleteProc);
    Tcl_SetObjResult(ip, objv[2]);
    return TCL_OK;
}

static int OmemoStoreCmd(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc < 2) {
        Tcl_WrongNumArgs(ip, 1, objv, "create name -device uint32");
        return TCL_ERROR;
    }
    const char *sub = Tcl_GetString(objv[1]);
    if (strcmp(sub, "create") == 0) return StoreCreate(ip, objc, objv);
    Tcl_SetObjResult(ip, Tcl_ObjPrintf("unknown subcommand: %s", sub));
    return TCL_ERROR;
}

static int StoreSerialize(Tcl_Interp *ip, PicoStore *ps) {
    size_t n = omemoGetSerializedStoreSize(&ps->base);
    Tcl_Obj *out = Tcl_NewByteArrayObj(NULL, (Tcl_Size)n);
    unsigned char *p = Tcl_SetByteArrayLength(out, (Tcl_Size)n);
    omemoSerializeStore(p, &ps->base);
    Tcl_SetObjResult(ip, out);
    return TCL_OK;
}

static int StoreDeserialize(Tcl_Interp *ip, PicoStore *ps, Tcl_Obj *blob) {
    Tcl_Size n = 0;
    unsigned char *p = Tcl_GetByteArrayFromObj(blob, &n);
    int rc = omemoDeserializeStore(p, (size_t)n, &ps->base);
    if (rc != 0) return SetOmemoError(ip, rc);
    return TCL_OK;
}

static int StoreBundle(Tcl_Interp *ip, PicoStore *ps) {
    Tcl_Obj *dict = Tcl_NewDictObj();
    Tcl_DictObjPut(NULL, dict, Tcl_NewStringObj("ik",     2),
                   Tcl_NewByteArrayObj(ps->base.identity.pub, 32));
    Tcl_DictObjPut(NULL, dict, Tcl_NewStringObj("spk",    3),
                   Tcl_NewByteArrayObj(ps->base.cursignedprekey.kp.pub, 32));
    Tcl_DictObjPut(NULL, dict, Tcl_NewStringObj("spk_id", 6),
                   Tcl_NewWideIntObj((Tcl_WideInt)ps->base.cursignedprekey.id));
    Tcl_DictObjPut(NULL, dict, Tcl_NewStringObj("spks",   4),
                   Tcl_NewByteArrayObj(ps->base.cursignedprekey.sig, 64));
    Tcl_Obj *list = Tcl_NewListObj(0, NULL);
    for (int i = 0; i < OMEMO_NUMPREKEYS; ++i) {
        struct omemoPreKey *pk = &ps->base.prekeys[i];
        if (pk->id == 0) continue;
        Tcl_Obj *entry = Tcl_NewListObj(0, NULL);
        Tcl_ListObjAppendElement(NULL, entry, Tcl_NewStringObj("id", 2));
        Tcl_ListObjAppendElement(NULL, entry, Tcl_NewWideIntObj((Tcl_WideInt)pk->id));
        Tcl_ListObjAppendElement(NULL, entry, Tcl_NewStringObj("pk", 2));
        Tcl_ListObjAppendElement(NULL, entry, Tcl_NewByteArrayObj(pk->kp.pub, 32));
        Tcl_ListObjAppendElement(NULL, list, entry);
    }
    Tcl_DictObjPut(NULL, dict, Tcl_NewStringObj("prekeys", 7), list);
    Tcl_SetObjResult(ip, dict);
    return TCL_OK;
}

static int StoreMarkPrekeyUsed(Tcl_Interp *ip, PicoStore *ps, Tcl_Obj *idObj) {
    Tcl_WideInt w = 0;
    if (Tcl_GetWideIntFromObj(ip, idObj, &w) != TCL_OK) return TCL_ERROR;
    uint32_t target = (uint32_t)w;
    for (int i = 0; i < OMEMO_NUMPREKEYS; ++i) {
        if (ps->base.prekeys[i].id == target) {
            SecureZero(&ps->base.prekeys[i], sizeof(ps->base.prekeys[i]));
            return TCL_OK;
        }
    }
    return TCL_OK;
}

static int StoreSubCmd(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    PicoStore *ps = (PicoStore *)cd;
    if (objc < 2) {
        Tcl_WrongNumArgs(ip, 1, objv, "subcommand ?args?");
        return TCL_ERROR;
    }
    const char *sub = Tcl_GetString(objv[1]);
    if (strcmp(sub, "setup") == 0) {
        if (objc != 2) { Tcl_WrongNumArgs(ip, 2, objv, NULL); return TCL_ERROR; }
        int rc = omemoSetupStore(&ps->base);
        if (rc != 0) return SetOmemoError(ip, rc);
        return TCL_OK;
    }
    if (strcmp(sub, "serialize") == 0) {
        if (objc != 2) { Tcl_WrongNumArgs(ip, 2, objv, NULL); return TCL_ERROR; }
        return StoreSerialize(ip, ps);
    }
    if (strcmp(sub, "deserialize") == 0) {
        if (objc != 3) { Tcl_WrongNumArgs(ip, 2, objv, "blob"); return TCL_ERROR; }
        return StoreDeserialize(ip, ps, objv[2]);
    }
    if (strcmp(sub, "identity_pub") == 0) {
        if (objc != 2) { Tcl_WrongNumArgs(ip, 2, objv, NULL); return TCL_ERROR; }
        Tcl_SetObjResult(ip, Tcl_NewByteArrayObj(ps->base.identity.pub, 32));
        return TCL_OK;
    }
    if (strcmp(sub, "device_id") == 0) {
        if (objc != 2) { Tcl_WrongNumArgs(ip, 2, objv, NULL); return TCL_ERROR; }
        Tcl_SetObjResult(ip, Tcl_NewWideIntObj((Tcl_WideInt)ps->device_id));
        return TCL_OK;
    }
    if (strcmp(sub, "bundle") == 0) {
        if (objc != 2) { Tcl_WrongNumArgs(ip, 2, objv, NULL); return TCL_ERROR; }
        return StoreBundle(ip, ps);
    }
    if (strcmp(sub, "rotate_signed_prekey") == 0) {
        if (objc != 2) { Tcl_WrongNumArgs(ip, 2, objv, NULL); return TCL_ERROR; }
        int rc = omemoRotateSignedPreKey(&ps->base);
        if (rc != 0) return SetOmemoError(ip, rc);
        return TCL_OK;
    }
    if (strcmp(sub, "refill_prekeys") == 0) {
        if (objc != 2) { Tcl_WrongNumArgs(ip, 2, objv, NULL); return TCL_ERROR; }
        int rc = omemoRefillPreKeys(&ps->base);
        if (rc != 0) return SetOmemoError(ip, rc);
        return TCL_OK;
    }
    if (strcmp(sub, "mark_prekey_used") == 0) {
        if (objc != 3) { Tcl_WrongNumArgs(ip, 2, objv, "pk_id"); return TCL_ERROR; }
        return StoreMarkPrekeyUsed(ip, ps, objv[2]);
    }
    if (strcmp(sub, "destroy") == 0) {
        if (objc != 2) { Tcl_WrongNumArgs(ip, 2, objv, NULL); return TCL_ERROR; }
        Tcl_DeleteCommandFromToken(ip, ps->cmd);
        return TCL_OK;
    }
    Tcl_SetObjResult(ip, Tcl_ObjPrintf("unknown store subcommand: %s", sub));
    return TCL_ERROR;
}

static int SessionCreate(Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    if (objc != 7) {
        Tcl_WrongNumArgs(ip, 2, objv, "name -jid bare -device uint32");
        return TCL_ERROR;
    }
    const char *name = Tcl_GetString(objv[2]);
    const char *jid = NULL;
    uint32_t dev = 0;
    int have_jid = 0, have_dev = 0;
    for (int i = 3; i < objc; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        if (strcmp(opt, "-jid") == 0)         { jid = Tcl_GetString(objv[i+1]); have_jid = 1; }
        else if (strcmp(opt, "-device") == 0) { if (ParseDevice(ip, objv[i+1], &dev) != TCL_OK) return TCL_ERROR; have_dev = 1; }
        else { Tcl_SetObjResult(ip, Tcl_ObjPrintf("unknown option: %s", opt)); return TCL_ERROR; }
    }
    if (!have_jid || !have_dev) {
        Tcl_SetObjResult(ip, Tcl_NewStringObj("both -jid and -device are required", -1));
        return TCL_ERROR;
    }
    PicoSession *ps = (PicoSession *)Tcl_Alloc(sizeof(*ps));
    memset(ps, 0, sizeof(*ps));
    ps->device_id = dev;
    size_t jl = strlen(jid);
    ps->jid = (char *)Tcl_Alloc(jl + 1);
    memcpy(ps->jid, jid, jl + 1);
    ps->cmd = Tcl_CreateObjCommand(ip, name, SessionSubCmd, ps, SessionDeleteProc);
    Tcl_SetObjResult(ip, objv[2]);
    return TCL_OK;
}

static int OmemoSessionCmd(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    (void)cd;
    if (objc < 2) {
        Tcl_WrongNumArgs(ip, 1, objv, "create name -jid bare -device uint32");
        return TCL_ERROR;
    }
    const char *sub = Tcl_GetString(objv[1]);
    if (strcmp(sub, "create") == 0) return SessionCreate(ip, objc, objv);
    Tcl_SetObjResult(ip, Tcl_ObjPrintf("unknown subcommand: %s", sub));
    return TCL_ERROR;
}

static int SessionInitiate(Tcl_Interp *ip, PicoSession *sess, int objc, Tcl_Obj *const objv[]) {
    /* <name> initiate <store> -ik -spk -spks -pk -spk-id -pk-id  -> objc == 15 */
    if (objc != 15) {
        Tcl_WrongNumArgs(ip, 2, objv,
            "store -ik bytes -spk bytes -spks bytes -pk bytes -spk-id int -pk-id int");
        return TCL_ERROR;
    }
    PicoStore *store = LookupStore(ip, objv[2]);
    if (!store) return TCL_ERROR;
    unsigned char *ik = NULL, *spk = NULL, *spks = NULL, *pk = NULL;
    Tcl_WideInt spk_id = 0, pk_id = 0;
    int have_ik=0, have_spk=0, have_spks=0, have_pk=0, have_spkid=0, have_pkid=0;
    for (int i = 3; i < objc; i += 2) {
        const char *opt = Tcl_GetString(objv[i]);
        Tcl_Obj *val = objv[i+1];
        if (strcmp(opt, "-ik") == 0) {
            if (CheckBytes(ip, val, 32, "-ik", &ik, NULL) != TCL_OK) return TCL_ERROR;
            have_ik = 1;
        } else if (strcmp(opt, "-spk") == 0) {
            if (CheckBytes(ip, val, 32, "-spk", &spk, NULL) != TCL_OK) return TCL_ERROR;
            have_spk = 1;
        } else if (strcmp(opt, "-spks") == 0) {
            if (CheckBytes(ip, val, 64, "-spks", &spks, NULL) != TCL_OK) return TCL_ERROR;
            have_spks = 1;
        } else if (strcmp(opt, "-pk") == 0) {
            if (CheckBytes(ip, val, 32, "-pk", &pk, NULL) != TCL_OK) return TCL_ERROR;
            have_pk = 1;
        } else if (strcmp(opt, "-spk-id") == 0) {
            if (Tcl_GetWideIntFromObj(ip, val, &spk_id) != TCL_OK) return TCL_ERROR;
            have_spkid = 1;
        } else if (strcmp(opt, "-pk-id") == 0) {
            if (Tcl_GetWideIntFromObj(ip, val, &pk_id) != TCL_OK) return TCL_ERROR;
            have_pkid = 1;
        } else {
            Tcl_SetObjResult(ip, Tcl_ObjPrintf("unknown option: %s", opt));
            return TCL_ERROR;
        }
    }
    if (!(have_ik && have_spk && have_spks && have_pk && have_spkid && have_pkid)) {
        Tcl_SetObjResult(ip, Tcl_NewStringObj("missing required option", -1));
        return TCL_ERROR;
    }
    omemoSerializedKey ik33, spk33, pk33;
    ik33[0]  = 0x05; memcpy(ik33  + 1, ik,  32);
    spk33[0] = 0x05; memcpy(spk33 + 1, spk, 32);
    pk33[0]  = 0x05; memcpy(pk33  + 1, pk,  32);
    omemoCurveSignature sig;
    memcpy(sig, spks, 64);
    int rc = omemoInitiateSession(&sess->base, &store->base,
                                  sig, spk33, ik33, pk33,
                                  (uint32_t)spk_id, (uint32_t)pk_id);
    if (rc != 0) return SetOmemoError(ip, rc);
    return TCL_OK;
}

static int SessionEncryptKey(Tcl_Interp *ip, PicoSession *sess, Tcl_Obj *payload) {
    Tcl_Size n = 0;
    unsigned char *p = Tcl_GetByteArrayFromObj(payload, &n);
    struct omemoKeyMessage msg;
    memset(&msg, 0, sizeof(msg));
    g_cb_err = 0;
    int rc = omemoEncryptKey(&sess->base, &msg, p, (size_t)n);
    if (rc != 0) return SetOmemoError(ip, rc);
    Tcl_Obj *dict = Tcl_NewDictObj();
    Tcl_DictObjPut(NULL, dict, Tcl_NewStringObj("p", 1),
                   Tcl_NewByteArrayObj(msg.p, (Tcl_Size)msg.n));
    Tcl_DictObjPut(NULL, dict, Tcl_NewStringObj("isprekey", 8),
                   Tcl_NewBooleanObj(msg.isprekey ? 1 : 0));
    Tcl_SetObjResult(ip, dict);
    return TCL_OK;
}

static int SessionDecryptKey(Tcl_Interp *ip, PicoSession *sess, int objc, Tcl_Obj *const objv[]) {
    /* <name> decrypt_key <store> <bytes> -prekey 0|1  -> objc == 6 */
    if (objc != 6) {
        Tcl_WrongNumArgs(ip, 2, objv, "store bytes -prekey 0|1");
        return TCL_ERROR;
    }
    PicoStore *store = LookupStore(ip, objv[2]);
    if (!store) return TCL_ERROR;
    Tcl_Size n = 0;
    unsigned char *msg = Tcl_GetByteArrayFromObj(objv[3], &n);
    if (strcmp(Tcl_GetString(objv[4]), "-prekey") != 0) {
        Tcl_SetObjResult(ip, Tcl_NewStringObj("expected -prekey", -1));
        return TCL_ERROR;
    }
    int isprekey = 0;
    if (Tcl_GetBooleanFromObj(ip, objv[5], &isprekey) != TCL_OK) return TCL_ERROR;
    uint8_t key[32];
    size_t keyn = sizeof(key);
    g_cb_err = 0;
    int rc = omemoDecryptKey(&sess->base, &store->base, key, &keyn,
                             (bool)isprekey, msg, (size_t)n);
    if (rc != 0) { SecureZero(key, sizeof(key)); return SetOmemoError(ip, rc); }
    Tcl_SetObjResult(ip, Tcl_NewByteArrayObj(key, (Tcl_Size)keyn));
    SecureZero(key, sizeof(key));
    return TCL_OK;
}

static int SessionHeartbeat(Tcl_Interp *ip, PicoSession *sess, Tcl_Obj *storeObj) {
    PicoStore *store = LookupStore(ip, storeObj);
    if (!store) return TCL_ERROR;
    struct omemoKeyMessage msg;
    memset(&msg, 0, sizeof(msg));
    g_cb_err = 0;
    int rc = omemoHeartbeat(&sess->base, &store->base, &msg);
    if (rc != 0) return SetOmemoError(ip, rc);
    if (msg.n == 0) Tcl_SetObjResult(ip, Tcl_NewObj());
    else            Tcl_SetObjResult(ip, Tcl_NewByteArrayObj(msg.p, (Tcl_Size)msg.n));
    return TCL_OK;
}

static int SessionSubCmd(ClientData cd, Tcl_Interp *ip, int objc, Tcl_Obj *const objv[]) {
    PicoSession *sess = (PicoSession *)cd;
    if (objc < 2) {
        Tcl_WrongNumArgs(ip, 1, objv, "subcommand ?args?");
        return TCL_ERROR;
    }
    const char *sub = Tcl_GetString(objv[1]);
    if (strcmp(sub, "initiate") == 0)        return SessionInitiate(ip, sess, objc, objv);
    if (strcmp(sub, "encrypt_key") == 0) {
        if (objc != 3) { Tcl_WrongNumArgs(ip, 2, objv, "payload"); return TCL_ERROR; }
        return SessionEncryptKey(ip, sess, objv[2]);
    }
    if (strcmp(sub, "decrypt_key") == 0)     return SessionDecryptKey(ip, sess, objc, objv);
    if (strcmp(sub, "heartbeat") == 0) {
        if (objc != 3) { Tcl_WrongNumArgs(ip, 2, objv, "store"); return TCL_ERROR; }
        return SessionHeartbeat(ip, sess, objv[2]);
    }
    if (strcmp(sub, "used_prekey_id") == 0) {
        if (objc != 2) { Tcl_WrongNumArgs(ip, 2, objv, NULL); return TCL_ERROR; }
        if (sess->base.usedpk_id == 0) Tcl_SetObjResult(ip, Tcl_NewObj());
        else Tcl_SetObjResult(ip, Tcl_NewWideIntObj((Tcl_WideInt)sess->base.usedpk_id));
        return TCL_OK;
    }
    if (strcmp(sub, "remote_identity") == 0) {
        if (objc != 2) { Tcl_WrongNumArgs(ip, 2, objv, NULL); return TCL_ERROR; }
        Tcl_SetObjResult(ip, Tcl_NewByteArrayObj(sess->base.remoteidentity, 32));
        return TCL_OK;
    }
    if (strcmp(sub, "serialize") == 0) {
        if (objc != 2) { Tcl_WrongNumArgs(ip, 2, objv, NULL); return TCL_ERROR; }
        size_t n = omemoGetSerializedSessionSize(&sess->base);
        Tcl_Obj *out = Tcl_NewByteArrayObj(NULL, (Tcl_Size)n);
        unsigned char *p = Tcl_SetByteArrayLength(out, (Tcl_Size)n);
        omemoSerializeSession(p, &sess->base);
        Tcl_SetObjResult(ip, out);
        return TCL_OK;
    }
    if (strcmp(sub, "deserialize") == 0) {
        if (objc != 3) { Tcl_WrongNumArgs(ip, 2, objv, "blob"); return TCL_ERROR; }
        Tcl_Size n = 0;
        unsigned char *p = Tcl_GetByteArrayFromObj(objv[2], &n);
        int rc = omemoDeserializeSession(p, (size_t)n, &sess->base);
        if (rc != 0) return SetOmemoError(ip, rc);
        return TCL_OK;
    }
    if (strcmp(sub, "destroy") == 0) {
        if (objc != 2) { Tcl_WrongNumArgs(ip, 2, objv, NULL); return TCL_ERROR; }
        Tcl_DeleteCommandFromToken(ip, sess->cmd);
        return TCL_OK;
    }
    Tcl_SetObjResult(ip, Tcl_ObjPrintf("unknown session subcommand: %s", sub));
    return TCL_ERROR;
}

int omemoRandom(void *p, size_t n) {
#ifdef _WIN32
    /* fills the whole buffer or fails, so no resume loop */
    NTSTATUS s = BCryptGenRandom(NULL, (PUCHAR)p, (ULONG)n,
                                 BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return BCRYPT_SUCCESS(s) ? 0 : OMEMO_ECRYPTO;
#else
    uint8_t *out = (uint8_t *)p;
    while (n > 0) {
        ssize_t r = getrandom(out, n, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            return OMEMO_ECRYPTO;
        }
        out += r;
        n   -= (size_t)r;
    }
    return 0;
#endif
}

int omemoLoadMessageKey(struct omemoSession *sess, struct omemoMessageKey *sk) {
    PicoSession *ps = (PicoSession *)sess;
    if (g_load_cmd == NULL || g_interp == NULL) return OMEMO_ESTATE;

    Tcl_Obj **prefv;
    Tcl_Size  prefc;
    if (Tcl_ListObjGetElements(g_interp, g_load_cmd, &prefc, &prefv) != TCL_OK) {
        g_cb_err = 1;
        return OMEMO_EUSER;
    }

    Tcl_Size argc = prefc + 4;
    Tcl_Obj **argv = (Tcl_Obj **)Tcl_Alloc(sizeof(Tcl_Obj *) * argc);
    for (Tcl_Size i = 0; i < prefc; ++i) argv[i] = prefv[i];
    argv[prefc + 0] = Tcl_NewStringObj(ps->jid ? ps->jid : "", -1);
    argv[prefc + 1] = Tcl_NewWideIntObj((Tcl_WideInt)ps->device_id);
    argv[prefc + 2] = Tcl_NewByteArrayObj(sk->dh, 32);
    argv[prefc + 3] = Tcl_NewWideIntObj((Tcl_WideInt)sk->nr);
    for (Tcl_Size i = 0; i < argc; ++i) Tcl_IncrRefCount(argv[i]);
    int code = Tcl_EvalObjv(g_interp, argc, argv, TCL_EVAL_GLOBAL);
    for (Tcl_Size i = 0; i < argc; ++i) Tcl_DecrRefCount(argv[i]);
    Tcl_Free((char *)argv);

    if (code != TCL_OK) { g_cb_err = 1; return OMEMO_EUSER; }
    Tcl_Obj *res = Tcl_GetObjResult(g_interp);
    Tcl_Size n = 0;
    unsigned char *bytes = Tcl_GetByteArrayFromObj(res, &n);
    if (n == 0) return 1;
    if (n != 32) {
        g_cb_err = 1;
        Tcl_SetObjResult(g_interp,
            Tcl_ObjPrintf("load callback returned %ld bytes, want 32", (long)n));
        return OMEMO_EUSER;
    }
    memcpy(sk->mk, bytes, 32);
    return 0;
}

int omemoStoreMessageKey(struct omemoSession *sess,
                         const struct omemoMessageKey *sk, uint64_t n) {
    PicoSession *ps = (PicoSession *)sess;
    if (g_store_cmd == NULL || g_interp == NULL) return OMEMO_ESTATE;

    Tcl_Obj **prefv;
    Tcl_Size  prefc;
    if (Tcl_ListObjGetElements(g_interp, g_store_cmd, &prefc, &prefv) != TCL_OK) {
        g_cb_err = 1;
        return OMEMO_EUSER;
    }

    Tcl_Size argc = prefc + 6;
    Tcl_Obj **argv = (Tcl_Obj **)Tcl_Alloc(sizeof(Tcl_Obj *) * argc);
    for (Tcl_Size i = 0; i < prefc; ++i) argv[i] = prefv[i];
    argv[prefc + 0] = Tcl_NewStringObj(ps->jid ? ps->jid : "", -1);
    argv[prefc + 1] = Tcl_NewWideIntObj((Tcl_WideInt)ps->device_id);
    argv[prefc + 2] = Tcl_NewByteArrayObj(sk->dh, 32);
    argv[prefc + 3] = Tcl_NewWideIntObj((Tcl_WideInt)sk->nr);
    argv[prefc + 4] = Tcl_NewByteArrayObj(sk->mk, 32);
    argv[prefc + 5] = Tcl_NewWideIntObj((Tcl_WideInt)n);
    for (Tcl_Size i = 0; i < argc; ++i) Tcl_IncrRefCount(argv[i]);
    int code = Tcl_EvalObjv(g_interp, argc, argv, TCL_EVAL_GLOBAL);
    for (Tcl_Size i = 0; i < argc; ++i) Tcl_DecrRefCount(argv[i]);
    Tcl_Free((char *)argv);

    if (code != TCL_OK) { g_cb_err = 1; return OMEMO_EUSER; }
    return 0;
}

DLLEXPORT int Omemo_Init(Tcl_Interp *interp) {
    if (Tcl_InitStubs(interp, "9.0", 0) == NULL) return TCL_ERROR;
    if (Tcl_CreateNamespace(interp, "::omemo", NULL, NULL) == NULL) {
        Tcl_ResetResult(interp);
    }
    Tcl_CreateObjCommand(interp, "::omemo::version",         OmemoVersionCmd,        NULL, NULL);
    Tcl_CreateObjCommand(interp, "::omemo::random",          OmemoRandomCmd,         NULL, NULL);
    Tcl_CreateObjCommand(interp, "::omemo::fingerprint",     OmemoFingerprintCmd,    NULL, NULL);
    Tcl_CreateObjCommand(interp, "::omemo::set_storage",     OmemoSetStorageCmd,     NULL, NULL);
    Tcl_CreateObjCommand(interp, "::omemo::encrypt_message", OmemoEncryptMessageCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::omemo::decrypt_message", OmemoDecryptMessageCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::omemo::media_encrypt",   MediaEncryptCmd,        NULL, NULL);
    Tcl_CreateObjCommand(interp, "::omemo::media_decrypt",   MediaDecryptCmd,        NULL, NULL);
    Tcl_CreateObjCommand(interp, "::omemo::store",           OmemoStoreCmd,          NULL, NULL);
    Tcl_CreateObjCommand(interp, "::omemo::session",         OmemoSessionCmd,        NULL, NULL);
    return Tcl_PkgProvide(interp, "omemo", PACKAGE_VERSION);
}
