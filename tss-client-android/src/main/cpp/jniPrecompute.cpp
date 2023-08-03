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
Java_com_web3auth_tss_1client_1android_dkls_Precompute_jniPrecomputeFromString(JNIEnv *env,
                                                                               jobject thiz,
                                                                               jbyteArray parties,
                                                                               jthrowable error) {
    // TODO: implement jniPrecomputeFromString()
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_web3auth_tss_1client_1android_dkls_Precompute_jniPrecomputeToString(JNIEnv *env,
                                                                             jobject thiz,
                                                                             jlong pointer,
                                                                             jthrowable error) {
    // TODO: implement jniPrecomputeToString()
}

extern "C"
JNIEXPORT void JNICALL
Java_com_web3auth_tss_1client_1android_dkls_Precompute_jniDklsStringFree(JNIEnv *env, jobject thiz,
                                                                         jbyteArray result) {
    // TODO: implement jniDklsStringFree()
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_web3auth_tss_1client_1android_dkls_Precompute_jnigetR_1FromPrecompute(JNIEnv *env,
                                                                               jobject thiz,
                                                                               jbyteArray precompute_bytes,
                                                                               jthrowable error) {
    // TODO: implement jnigetR_FromPrecompute()
}

extern "C"
JNIEXPORT void JNICALL
Java_com_web3auth_tss_1client_1android_dkls_Precompute_jniPrecomputeFree(JNIEnv *env, jobject thiz,
                                                                         jlong pointer) {
    jlong pObject = GetPointerField(env, thiz);
    auto pGenerator = reinterpret_cast<Precompute *>(pObject);
    precompute_free(pGenerator);
}