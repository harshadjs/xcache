LOCAL_PATH := $(call my-dir)
  subdirs := $(addprefix $(LOCAL_PATH)/,$(addsuffix /Android.mk, \
        android-deps \
        click \
        api \
  ))
include $(subdirs)