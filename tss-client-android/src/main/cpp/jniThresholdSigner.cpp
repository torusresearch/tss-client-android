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
Java_com_web3auth_tss_1client_1android_dkls_ThresholdSigner_jniThreaholdSigner(JNIEnv *env,
                                                                               jobject thiz,
                                                                               jbyteArray session_bytes,
                                                                               jint player_index,
                                                                               jint parties,
                                                                               jint threshold,
                                                                               jbyteArray share_bytes,
                                                                               jbyteArray pk_bytes,
                                                                               jthrowable dkls_error) {
    // TODO: implement jniThreaholdSigner()
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_web3auth_tss_1client_1android_dkls_ThresholdSigner_jniThresholdSignerSetup(JNIEnv *env,
                                                                                    jobject thiz,
                                                                                    jlong ptr,
                                                                                    jlong chacha_ptr,
                                                                                    jlong dkls_comm_ptr,
                                                                                    jthrowable dkls_error) {
    // TODO: implement jniThresholdSignerSetup()
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_web3auth_tss_1client_1android_dkls_ThresholdSigner_jniThresholdSignerPrecompute(
        JNIEnv *env, jobject thiz, jlong counter_parties_ptr, jlong ptr, jlong chacha_ptr,
        jlong dkls_comm_ptr, jthrowable dkls_error) {
    // TODO: implement jniThresholdSignerPrecompute()
}

extern "C"
JNIEXPORT void JNICALL
Java_com_web3auth_tss_1client_1android_dkls_ThresholdSigner_jniDkls_1string_1free(JNIEnv *env,
                                                                                  jobject thiz,
                                                                                  jbyteArray result) {
    // TODO: implement jniDkls_string_free()
}

extern "C"
JNIEXPORT void JNICALL
Java_com_web3auth_tss_1client_1android_dkls_ThresholdSigner_jniThresholdSignerFree(JNIEnv *env,
                                                                                   jobject thiz) {
    jlong pObject = GetPointerField(env, thiz);
    auto pGenerator = reinterpret_cast<ThresholdSigner *>(pObject);
    threshold_signer_free(pGenerator);
}