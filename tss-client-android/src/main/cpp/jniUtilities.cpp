//
// Created by grvgo on 28-07-2023.
//
#include <jni.h>
#include "include/dkls.h"
#include <string>
#include <cmath>
#include "jniCommon.cpp"

extern "C"
JNIEXPORT jint JNICALL
Java_com_web3auth_tss_1client_1android_dkls_Utilities_jniDklsBatchSize(JNIEnv *env, jclass clazz,
                                                                       jthrowable dkls_error) {
    // TODO: implement jniDklsBatchSize()
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_web3auth_tss_1client_1android_dkls_Utilities_jniDklsHashEncode(JNIEnv *env, jclass clazz,
                                                                        jbyteArray msg,
                                                                        jthrowable dkls_error) {
    // TODO: implement jniDklsHashEncode()
}


extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_web3auth_tss_1client_1android_dkls_Utilities_jniDklsLocalSign(JNIEnv *env, jclass clazz,
                                                                       jbyteArray msg,
                                                                       jboolean hash_only,
                                                                       jbyteArray precompute_bytes,
                                                                       jthrowable dkls_error) {
    // TODO: implement jniDklsLocalSign()
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_web3auth_tss_1client_1android_dkls_Utilities_jniDklsLocalVerify(JNIEnv *env, jclass clazz,
                                                                         jbyteArray msg,
                                                                         jboolean hash_only,
                                                                         jbyteArray precompute_bytes,
                                                                         jlong sig_frags_ptr,
                                                                         jbyteArray pk_bytes,
                                                                         jthrowable dkls_error) {
    // TODO: implement jniDklsLocalVerify()
}

extern "C"
JNIEXPORT void JNICALL
Java_com_web3auth_tss_1client_1android_dkls_Utilities_jniDklsStringFree(JNIEnv *env, jclass clazz,
                                                                        jbyteArray result) {
    // TODO: implement jniDklsStringFree()
}