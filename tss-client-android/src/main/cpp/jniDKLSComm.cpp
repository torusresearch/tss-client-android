//
// Created by grvgo on 28-07-2023.
//
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

jobject handler = nullptr;
jmethodID sendMsgCallbackID;
jmethodID readMsgCallbackID;

// Note:
// readMsgCallback(session, index, remote, msg_type) -> msg_data
// sendMsgCallback(session, index, recipient, msg_type, msg_data) -> Bool

const char* readMsgCallback(const char* session, unsigned long long int index, unsigned long long int remote, const char* msg_type) {
    JNIEnv *jniEnv;

    if (g_vm->GetEnv((void **) &jniEnv, JNI_VERSION_1_6) != JNI_OK || handler == nullptr) {
        return "";
    }

    jstring jsession = jniEnv->NewStringUTF(session);
    dkls_string_free(const_cast<char*>(session));

    jstring jmsgType = jniEnv->NewStringUTF(msg_type);
    dkls_string_free(const_cast<char*>(msg_type));

    auto jparent_ref = reinterpret_cast<jobject>(handler);
    auto result = (jstring) jniEnv->CallObjectMethod(
            jparent_ref,
            readMsgCallbackID,
            jsession, index, remote, jmsgType);
    char *res = const_cast<char *>(jniEnv->GetStringUTFChars(result, JNI_FALSE));
    jniEnv->DeleteLocalRef(result);
    return res;
}

bool sendMsgCallback(const char* session, unsigned long long int index, unsigned long long int remote, const char* msg_type, const char* msg_data) {
    JNIEnv *jniEnv;

    if (g_vm->GetEnv((void **) &jniEnv, JNI_VERSION_1_6) != JNI_OK || handler == nullptr) {
        return false;
    }

    jstring jsession = jniEnv->NewStringUTF(session);
    dkls_string_free(const_cast<char*>(session));

    jstring jmsgType = jniEnv->NewStringUTF(msg_type);
    dkls_string_free(const_cast<char*>(msg_type));

    jstring jmsgData = jniEnv->NewStringUTF(msg_data);
    dkls_string_free(const_cast<char*>(msg_data));

    auto jparent_ref = reinterpret_cast<jobject>(handler);
    auto result = (jstring) jniEnv->CallObjectMethod(
            jparent_ref,
            sendMsgCallbackID,
            jsession, index, remote, jmsgType, jmsgData);
    bool res = result;
    jniEnv->DeleteLocalRef(result);
    return res;

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
    handler = env->NewGlobalRef(thiz);
    sendMsgCallbackID = getMethodId(
            env,
            thiz,
            send_msg_callback,
            send_msg_callback_sig);
    readMsgCallbackID = getMethodId(
            env,
            thiz,
            read_msg_callback,
            read_msg_callback_sig);

    const char *pSession = env->GetStringUTFChars(session, JNI_FALSE);
    auto *pResult = dkls_comm(index,parties,pSession,readMsgCallback,sendMsgCallback,error_ptr);
    env->ReleaseStringUTFChars(session, pSession);
    setErrorCode(env, dkls_error, errorCode);
    return reinterpret_cast<jlong>(pResult);
}

extern "C"
JNIEXPORT void JNICALL
Java_com_web3auth_tss_1client_1android_dkls_DKLSComm_jniDklsCommFree(JNIEnv *env, jobject thiz) {
    env->DeleteGlobalRef(handler);
    handler = nullptr;
    jlong pObject = GetPointerField(env, thiz);
    auto pObj = reinterpret_cast<DKLSMsgComm *>(pObject);
    dkls_comm_free(pObj);
}