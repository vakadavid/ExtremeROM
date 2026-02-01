if [[ "$SOURCE_AUTO_BRIGHTNESS_TYPE" != "$TARGET_AUTO_BRIGHTNESS_TYPE" && "$TARGET_AUTO_BRIGHTNESS_TYPE" != "4" ]]; then
    LOG_STEP_IN "- Applying auto brightness type patches"

    DECODE_APK "system" "system/framework/services.jar"
    DECODE_APK "system" "system/framework/ssrm.jar"
    DECODE_APK "system" "system/priv-app/SecSettings/SecSettings.apk"

    FTP="
    system/framework/services.jar/smali_classes2/com/android/server/power/PowerManagerUtil.smali
    system/framework/ssrm.jar/smali/com/android/server/ssrm/PreMonitor.smali
    system/priv-app/SecSettings/SecSettings.apk/smali_classes4/com/samsung/android/settings/Rune.smali
    "
    for f in $FTP; do
        sed -i "s/\"$SOURCE_AUTO_BRIGHTNESS_TYPE\"/\"$TARGET_AUTO_BRIGHTNESS_TYPE\"/g" "$APKTOOL_DIR/$f"
    done

    # WORKAROUND: Skip failure on CALIBRATEDLUX
    # mov this,0x1 -> mov this,0x0
    if [[ "$TARGET_AUTO_BRIGHTNESS_TYPE" == "3" ]]; then
        HEX_PATCH "$WORK_DIR/system/system/lib64/libsensorservice.so" "074B009420008052" "074B009400008052"
    fi
    LOG_STEP_OUT
fi

DECODE_APK "system" "system/framework/framework.jar"

if [[ "$TARGET_HFR_SEAMLESS_BRT" == "none" && "$TARGET_HFR_SEAMLESS_LUX" == "none" ]]; then
     APPLY_PATCH "system" "system/framework/framework.jar" "$SRC_DIR/unica/patches/product_feature/hfr/framework.jar/0001-Remove-brightness-threshold-values.patch"
else

FTP="
system/framework/framework.jar/smali_classes6/com/samsung/android/hardware/display/RefreshRateConfig.smali
"
for f in $FTP; do
    sed -i "s/\"$SOURCE_HFR_SEAMLESS_BRT\"/\"$TARGET_HFR_SEAMLESS_BRT\"/g" "$APKTOOL_DIR/$f"
    sed -i "s/\"$SOURCE_HFR_SEAMLESS_LUX\"/\"$TARGET_HFR_SEAMLESS_LUX\"/g" "$APKTOOL_DIR/$f"
done
fi

if [[ "$SOURCE_HFR_MODE" != "$TARGET_HFR_MODE" ]]; then
    LOG_STEP_IN "- Applying HFR_MODE patches"

    DECODE_APK "system" "system/framework/framework.jar"
    DECODE_APK "system" "system/framework/gamemanager.jar"
    DECODE_APK "system" "system/framework/secinputdev-service.jar"
    DECODE_APK "system" "system/priv-app/SecSettings/SecSettings.apk"
    DECODE_APK "system" "system/priv-app/SettingsProvider/SettingsProvider.apk"
    DECODE_APK "system_ext" "priv-app/SystemUI/SystemUI.apk"

    FTP="
    system/framework/framework.jar/smali_classes6/com/samsung/android/hardware/display/RefreshRateConfig.smali
    system/framework/framework.jar/smali_classes6/com/samsung/android/rune/CoreRune.smali
    system/framework/gamemanager.jar/smali/com/samsung/android/game/GameManagerService.smali
    system/framework/secinputdev-service.jar/smali/com/samsung/android/hardware/secinputdev/SemInputDeviceManagerService.smali
    system/framework/secinputdev-service.jar/smali/com/samsung/android/hardware/secinputdev/utils/SemInputFeatures.smali
    system/framework/secinputdev-service.jar/smali/com/samsung/android/hardware/secinputdev/utils/SemInputFeaturesExtra.smali
    system/priv-app/SecSettings/SecSettings.apk/smali_classes4/com/samsung/android/settings/display/SecDisplayUtils.smali
    system/priv-app/SettingsProvider/SettingsProvider.apk/smali/com/android/providers/settings/DatabaseHelper.smali
    system_ext/priv-app/SystemUI/SystemUI.apk/smali/com/android/systemui/LsRune.smali
    "
    for f in $FTP; do
        sed -i "s/\"$SOURCE_HFR_MODE\"/\"$TARGET_HFR_MODE\"/g" "$APKTOOL_DIR/$f"
    done

    LOG_STEP_OUT
fi

if [[ "$SOURCE_HFR_SUPPORTED_REFRESH_RATE" != "$TARGET_HFR_SUPPORTED_REFRESH_RATE" ]]; then
    LOG_STEP_IN "- Applying HFR_SUPPORTED_REFRESH_RATE patches"

    DECODE_APK "system" "system/framework/framework.jar"
    DECODE_APK "system" "system/priv-app/SecSettings/SecSettings.apk"

    FTP="
    system/framework/framework.jar/smali_classes6/com/samsung/android/hardware/display/RefreshRateConfig.smali
    system/priv-app/SecSettings/SecSettings.apk/smali_classes4/com/samsung/android/settings/display/SecDisplayUtils.smali
    "
    for f in $FTP; do
        if [[ "$TARGET_HFR_SUPPORTED_REFRESH_RATE" != "none" ]]; then
            sed -i "s/\"$SOURCE_HFR_SUPPORTED_REFRESH_RATE\"/\"$TARGET_HFR_SUPPORTED_REFRESH_RATE\"/g" "$APKTOOL_DIR/$f"
        else
            sed -i "s/\"$SOURCE_HFR_SUPPORTED_REFRESH_RATE\"/\"\"/g" "$APKTOOL_DIR/$f"
        fi
    done
    LOG_STEP_OUT
fi
if [[ "$SOURCE_HFR_DEFAULT_REFRESH_RATE" != "$TARGET_HFR_DEFAULT_REFRESH_RATE" ]]; then
    LOG_STEP_IN "- Applying HFR_DEFAULT_REFRESH_RATE patches"

    DECODE_APK "system" "system/framework/framework.jar"
    DECODE_APK "system" "system/priv-app/SecSettings/SecSettings.apk"
    DECODE_APK "system" "system/priv-app/SettingsProvider/SettingsProvider.apk"

    FTP="
    system/framework/framework.jar/smali_classes6/com/samsung/android/hardware/display/RefreshRateConfig.smali
    system/priv-app/SecSettings/SecSettings.apk/smali_classes4/com/samsung/android/settings/display/SecDisplayUtils.smali
    system/priv-app/SettingsProvider/SettingsProvider.apk/smali/com/android/providers/settings/DatabaseHelper.smali
    "
    for f in $FTP; do
        sed -i "s/\"$SOURCE_HFR_DEFAULT_REFRESH_RATE\"/\"$TARGET_HFR_DEFAULT_REFRESH_RATE\"/g" "$APKTOOL_DIR/$f"
    done
    LOG_STEP_OUT
fi

if [[ "$TARGET_DISPLAY_CUTOUT_TYPE" == "right" ]]; then
    LOG_STEP_IN "- Applying right cutout patch"
    APPLY_PATCH "system_ext" "priv-app/SystemUI/SystemUI.apk" "$SRC_DIR/unica/patches/product_feature/cutout/SystemUI.apk/0001-Add-right-cutout-support.patch"
    LOG_STEP_OUT
fi

if [[ "$SOURCE_DVFS_CONFIG_NAME" != "$TARGET_DVFS_CONFIG_NAME" ]]; then
    LOG_STEP_IN "- Applying DVFS patches"

    DECODE_APK "system" "system/framework/ssrm.jar"

    FTP="
    system/framework/ssrm.jar/smali/com/android/server/ssrm/Feature.smali
    "
    for f in $FTP; do
        sed -i "s/\"$SOURCE_DVFS_CONFIG_NAME\"/\"$TARGET_DVFS_CONFIG_NAME\"/g" "$APKTOOL_DIR/$f"
    done
    LOG_STEP_OUT
fi

if $SOURCE_IS_ESIM_SUPPORTED; then
    if ! $TARGET_IS_ESIM_SUPPORTED; then
        SET_FLOATING_FEATURE_CONFIG "SEC_FLOATING_FEATURE_COMMON_CONFIG_EMBEDDED_SIM_SLOTSWITCH" --delete
        SET_FLOATING_FEATURE_CONFIG "SEC_FLOATING_FEATURE_COMMON_SUPPORT_EMBEDDED_SIM" --delete
    fi
fi

if [ -f "$FW_DIR/${MODEL}_${REGION}/system/system/etc/permissions/com.sec.feature.cover.xml" ]; then
    LOG_STEP_IN "- Adding LED Case Cover support"
    ADD_TO_WORK_DIR "p3sxxx" "system" "system/priv-app/LedCoverService/LedCoverService.apk"
    ADD_TO_WORK_DIR "p3sxxx" "system" "system/etc/permissions/privapp-permissions-com.sec.android.cover.ledcover.xml"
    LOG_STEP_OUT
fi

if [ ! -f "$FW_DIR/${MODEL}_${REGION}/vendor/etc/permissions/android.hardware.strongbox_keystore.xml" ]; then
    LOG_STEP_IN "- Applying strongbox patches"
    APPLY_PATCH "system" "system/framework/framework.jar" "$SRC_DIR/unica/patches/product_feature/strongbox/framework.jar/0001-Disable-StrongBox-in-DevRootKeyATCmd.patch"
    LOG_STEP_OUT
fi

if $SOURCE_SUPPORT_HOTSPOT_WPA3; then
    if ! $TARGET_SUPPORT_HOTSPOT_WPA3; then
        LOG_STEP_IN "- Applying Hotspot WPA3 patches"
        APPLY_PATCH "system" "system/framework/semwifi-service.jar" "$SRC_DIR/unica/patches/product_feature/wifi/semwifi-service.jar/0002-Disable-Hotspot-WPA3-support.patch"
        LOG_STEP_OUT
    fi
fi

if $SOURCE_SUPPORT_HOTSPOT_6GHZ; then
    if ! $TARGET_SUPPORT_HOTSPOT_6GHZ; then
        LOG_STEP_IN "- Applying Hotspot 6GHz patches"
        APPLY_PATCH "system" "system/framework/semwifi-service.jar" "$SRC_DIR/unica/patches/product_feature/wifi/semwifi-service.jar/0003-Disable-Hotspot-6GHz-support.patch"
        LOG_STEP_OUT
    fi
fi

# if $SOURCE_SUPPORT_HOTSPOT_WIFI_6; then
#     if ! $TARGET_SUPPORT_HOTSPOT_WIFI_6; then
#         LOG_STEP_IN "- Applying Hotspot Wi-Fi 6 patches"
#         APPLY_PATCH "system" "system/priv-app/SecSettings/SecSettings.apk" "$SRC_DIR/unica/patches/product_feature/wifi/SecSettings.apk/0002-Disable-Hotspot-Wi-Fi-6.patch"
#         LOG_STEP_OUT
#     fi
# fi

if ! $SOURCE_AUDIO_SUPPORT_ACH_RINGTONE; then
    if $TARGET_AUDIO_SUPPORT_ACH_RINGTONE; then
        LOG_STEP_IN "- Applying ACH ringtone patches"
        APPLY_PATCH "system" "system/framework/framework.jar" "$SRC_DIR/unica/patches/product_feature/audio/framework.jar/0001-Enable-ACH-ringtone-support.patch"

        LOG "- Extracting ACH ringtone assets"
        DELETE_FROM_WORK_DIR "system" "system/media/audio/ringtones"
        DELETE_FROM_WORK_DIR "system" "system/media/audio/notifications"
        ADD_TO_WORK_DIR "q7qzcx" "system" "system/media/audio/ringtones"
        ADD_TO_WORK_DIR "q7qzcx" "system" "system/media/audio/notifications"
        SET_PROP "vendor" "ro.config.ringtone" "ACH_Galaxy_Bells.ogg"
        SET_PROP "vendor" "ro.config.notification_sound" "ACH_Brightline.ogg"
        SET_PROP "vendor" "ro.config.alarm_alert" "ACH_Morning_Xylophone.ogg"
        SET_PROP "vendor" "ro.config.ringtone_2" "ACH_Atomic_Bell.ogg"
        SET_PROP "vendor" "ro.config.notification_sound_2" "ACH_Three_Star.ogg"
        LOG_STEP_OUT
    fi
fi

