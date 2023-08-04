//
// Created by grvgo on 28-07-2023.
//
#include <jni.h>
#include "include/dkls.h"
#include <string>
#include <cmath>
#include "jniCommon.cpp"

extern "C"
JNIEXPORT jlong JNICALL
Java_com_web3auth_tss_1client_1android_dkls_DKLSComm_jniDklsComm(JNIEnv *env, jobject thiz,
                                                                 jint index, jint parties,
                                                                 jstring sessions,
                                                                 jobject read_msg_callback,
                                                                 jobject send_msg_callback,
                                                                 jthrowable dkls_error) {
    // TODO: implement jniDklsComm()
}

extern "C"
JNIEXPORT void JNICALL
Java_com_web3auth_tss_1client_1android_dkls_DKLSComm_jniDklsCommFree(JNIEnv *env, jobject thiz) {
    // TODO: implement jniDklsCommFree()
    jlong pObject = GetPointerField(env, thiz);
    auto pObj = reinterpret_cast<DKLSMsgComm *>(pObject);
    dkls_comm_free(pObj);
}