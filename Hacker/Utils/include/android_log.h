#ifndef ANDROID_LOG_H
#define ANDROID_LOG_H

#include <android/log.h>

#define DEBUG
#ifdef DEBUG
#define LOGV(LOG_TAG, ...) \
  (void)__android_log_print(ANDROID_LOG_VERBOSE, LOG_TAG, __VA_ARGS__)
#define LOGD(LOG_TAG, ...) \
  (void)__android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGI(LOG_TAG, ...) \
  (void)__android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(LOG_TAG, ...) \
  (void)__android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(LOG_TAG, ...) \
  (void)__android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#else
#define LOGV(LOG_TAG, ...) NULL
#define LOGD(LOG_TAG, ...) NULL
#define LOGI(LOG_TAG, ...) NULL
#define LOGW(LOG_TAG, ...) NULL
#define LOGE(LOG_TAG, ...) NULL
#endif

#endif