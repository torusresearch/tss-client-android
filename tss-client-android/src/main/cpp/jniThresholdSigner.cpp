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
Java_com_web3auth_tss_1client_1android_dkls_ThresholdSigner_jniThresholdSigner(JNIEnv *env,
                                                                               jobject thiz,
                                                                               jstring session,
                                                                               jint player_index,
                                                                               jint parties,
                                                                               jint threshold,
                                                                               jstring share,
                                                                               jstring pk,
                                                                               jthrowable dkls_error) {
    int errorCode = 0;
    int *error_ptr = &errorCode;
    const char *pSession = env->GetStringUTFChars(session, JNI_FALSE);
    const char *pShare = env->GetStringUTFChars(share, JNI_FALSE);
    const char *pPubKey = env->GetStringUTFChars(pk, JNI_FALSE);
    auto *pResult = threshold_signer(pSession,player_index,parties,threshold,pShare,pPubKey, error_ptr);
    env->ReleaseStringUTFChars(session, pSession);
    env->ReleaseStringUTFChars(share, pShare);
    env->ReleaseStringUTFChars(pk, pPubKey);
    setErrorCode(env, dkls_error, errorCode);
    return reinterpret_cast<jlong>(pResult);
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_web3auth_tss_1client_1android_dkls_ThresholdSigner_jniThresholdSignerSetup(JNIEnv *env,jobject thiz,jobject chacha,jobject dkls_comm, jthrowable dkls_error) {
    jlong pSigner = GetPointerField(env, thiz);
    auto signer = reinterpret_cast<ThresholdSigner *>(pSigner);
    jlong pRng = GetPointerField(env, chacha);
    auto rng = reinterpret_cast<ChaChaRng *>(pRng);
    jlong pComm = GetPointerField(env, dkls_comm);
    auto comm = reinterpret_cast<DKLSMsgComm *>(pComm);
    bool result = threshold_signer_setup(signer,rng,comm);
    return result;
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_web3auth_tss_1client_1android_dkls_ThresholdSigner_jniThresholdSignerPrecompute(
        JNIEnv *env, jobject thiz, jobject counter_parties, jobject chacha,
        jobject dkls_comm, jthrowable dkls_error) {
    int errorCode = 0;
    int *error_ptr = &errorCode;
    jlong pSigner = GetPointerField(env, thiz);
    auto signer = reinterpret_cast<ThresholdSigner *>(pSigner);
    jlong pRng = GetPointerField(env, chacha);
    auto rng = reinterpret_cast<ChaChaRng *>(pRng);
    jlong pComm = GetPointerField(env, dkls_comm);
    auto comm = reinterpret_cast<DKLSMsgComm *>(pComm);
    jlong pCounterParties = GetPointerField(env, counter_parties);
    auto counterparties = reinterpret_cast<Counterparties *>(pCounterParties);
    const char* pResult = threshold_signer_precompute(counterparties,signer,rng,comm,error_ptr);
    setErrorCode(env, dkls_error, errorCode);
    jstring result = env->NewStringUTF(pResult);
    dkls_string_free(const_cast<char*>(pResult));
    return result;
}

extern "C"
JNIEXPORT void JNICALL
Java_com_web3auth_tss_1client_1android_dkls_ThresholdSigner_jniThresholdSignerFree(JNIEnv *env, jobject thiz) {
    jlong pObject = GetPointerField(env, thiz);
    auto pObj = reinterpret_cast<ThresholdSigner *>(pObject);
    threshold_signer_free(pObj);
}