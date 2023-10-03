#include <jni.h>
#include "include/dkls.h"
#include <string>
#include <cmath>
#include "jniCommon.cpp"

JavaVM *g_vm;

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *) {
    g_vm = vm;
    return JNI_VERSION_1_6;
}

// Note:
// readMsgCallback(session, index, remote, msg_type) -> msg_data
// sendMsgCallback(session, index, recipient, msg_type, msg_data) -> Bool

const char* readMsgCallback(const char* session, unsigned long long int index, unsigned long long int remote, const char* msg_type, const void *obj_ref) {
    JNIEnv *jniEnv;

    if (g_vm->GetEnv((void **) &jniEnv, JNI_VERSION_1_6) != JNI_OK || obj_ref == nullptr) {
        return "";
    }

    jstring jsession = jniEnv->NewStringUTF(session);
    dkls_string_free(const_cast<char*>(session));

    jstring jmsgType = jniEnv->NewStringUTF(msg_type);
    dkls_string_free(const_cast<char*>(msg_type));

    auto jparent_ref = reinterpret_cast<jobject>(const_cast<void*>(obj_ref));
    auto index_bytes = getBytesFromUnsignedLongLong(jniEnv, index);
    auto remote_bytes = getBytesFromUnsignedLongLong(jniEnv, remote);

    auto readMsgCallbackID = reinterpret_cast<jmethodID>(GetPointerField(jniEnv,
                                                                        jparent_ref,
                                                                        "read_callback_id"));
    auto result = (jstring) jniEnv->CallObjectMethod(
            jparent_ref,
            readMsgCallbackID,
            jsession, index_bytes, remote_bytes, jmsgType);
    char *res = const_cast<char *>(jniEnv->GetStringUTFChars(result, JNI_FALSE));
    jniEnv->DeleteLocalRef(result);
    return res;
}

bool sendMsgCallback(const char* session, unsigned long long int index, unsigned long long int remote, const char* msg_type, const char* msg_data, const void *obj_ref) {
    JNIEnv *jniEnv;

    if (g_vm->GetEnv((void **) &jniEnv, JNI_VERSION_1_6) != JNI_OK || obj_ref == nullptr) {
        return false;
    }

    jstring jsession = jniEnv->NewStringUTF(session);
    dkls_string_free(const_cast<char*>(session));

    jstring jmsgType = jniEnv->NewStringUTF(msg_type);
    dkls_string_free(const_cast<char*>(msg_type));

    jstring jmsgData = jniEnv->NewStringUTF(msg_data);
    dkls_string_free(const_cast<char*>(msg_data));

    auto index_bytes = getBytesFromUnsignedLongLong(jniEnv, index);
    auto remote_bytes = getBytesFromUnsignedLongLong(jniEnv, remote);

    auto jparent_ref = reinterpret_cast<jobject>(const_cast<void*>(obj_ref));
    auto sendMsgCallbackID = reinterpret_cast<jmethodID>(GetPointerField(jniEnv,
                                                                         jparent_ref,
                                                                         "send_callback_id"));
    auto result = jniEnv->CallBooleanMethod(
            jparent_ref,
            sendMsgCallbackID,
            jsession, index_bytes, remote_bytes, jmsgType, jmsgData);
    return result;

}

extern "C"
JNIEXPORT jlong JNICALL
Java_com_web3auth_tss_1client_1android_dkls_DKLSComm_jniDklsComm(JNIEnv *env, jobject thiz,
                                                                 jint index, jint parties,
                                                                 jstring session,
                                                                 jstring read_msg_callback,
                                                                 jstring read_msg_callback_sig,
                                                                 jstring send_msg_callback,
                                                                 jstring send_msg_callback_sig,
                                                                 jthrowable dkls_error) {
    int errorCode = 0;
    int *error_ptr = &errorCode;
    jobject instance = env->NewGlobalRef(thiz);

    jmethodID sendMsgCallbackID = getMethodId(
            env,
            instance,
            send_msg_callback,
            send_msg_callback_sig);
    SetPointerField(env, instance, reinterpret_cast<jlong>(sendMsgCallbackID), "send_callback_id");
    jmethodID readMsgCallbackID = getMethodId(
            env,
            instance,
            read_msg_callback,
            read_msg_callback_sig);
    SetPointerField(env, instance, reinterpret_cast<jlong>(readMsgCallbackID), "read_callback_id");

    const char *pSession = env->GetStringUTFChars(session, JNI_FALSE);
    auto *pResult = dkls_comm(index,parties,pSession,readMsgCallback,sendMsgCallback,instance,error_ptr);
    env->ReleaseStringUTFChars(session, pSession);
    setErrorCode(env, dkls_error, errorCode);
    return reinterpret_cast<jlong>(pResult);
}

extern "C"
JNIEXPORT void JNICALL
Java_com_web3auth_tss_1client_1android_dkls_DKLSComm_jniDklsCommFree(JNIEnv *env, jobject thiz) {
    jlong pObject = GetPointerField(env, thiz);
    auto pObj = reinterpret_cast<DKLSMsgComm *>(pObject);
    auto instance = dkls_comm_free(pObj);
    if (instance != nullptr) {
        auto obj_ref = reinterpret_cast<jobject>(const_cast<void*>(instance));
        env->DeleteGlobalRef(obj_ref);
    }
}