#
# Copyright (C) 2023 Salvo Giangreco
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

# UN1CA debloat list
# - Add entries inside the specific partition containing that file (<PARTITION>_DEBLOAT+="")
# - DO NOT add the partition name at the start of any entry (eg. "/system/dpolicy_system")
# - DO NOT add a slash at the start of any entry (eg. "/dpolicy_system")

# Samsung Defex policy
SYSTEM_DEBLOAT+="
dpolicy_system
"

VENDOR_DEBLOAT+="
etc/dpolicy
"

# Samsung SIM Unlock
SYSTEM_DEBLOAT+="
system/bin/ssud
system/etc/init/ssu_r12sxxx.rc
system/etc/init/ssu.rc
system/etc/permissions/privapp-permissions-com.samsung.ssu.xml
system/etc/sysconfig/samsungsimunlock.xml
system/lib64/android.security.securekeygeneration-ndk.so
system/lib64/vendor.samsung.hardware.security.ssu-V1-ndk.so
system/lib64/libssu_keystore2.so
system/priv-app/SsuService
"

# Samsung Language Core
SYSTEM_DEBLOAT+="
system/etc/permissions/signature-permissions-com.samsung.android.offline.languagemodel.xml
system/priv-app/OfflineLanguageModel_stub
"

# PDP apps
SYSTEM_DEBLOAT+="
system/preload
"

# Live Transcribe
SYSTEM_DEBLOAT+="
system/app/LiveTranscribe
system/etc/sysconfig/feature-a11y-preload.xml
"

# SVC Agent
SYSTEM_DEBLOAT+="
system/etc/permissions/privapp-permissions-com.samsung.android.svcagent.xml
system/priv-app/SVCAgent
"

# Samsung Messages
SYSTEM_DEBLOAT+="
system/etc/default-permissions/default-permissions-com.samsung.android.messaging.xml
system/etc/permissions/privapp-permissions-com.samsung.android.messaging.xml
system/priv-app/SamsungMessages
"

# Voice Access
SYSTEM_DEBLOAT+="
system/app/VoiceAccess
system/etc/sysconfig/feature-a11y-preload-voacc.xml
"

# Smart Touch Call
SYSTEM_DEBLOAT+="
system/etc/default-permissions/default-permissions-com.samsung.android.visualars.xml
system/etc/permissions/privapp-permissions-com.samsung.android.visualars.xml
system/priv-app/SmartTouchCall
"

# Samsung Analytics
SYSTEM_DEBLOAT+="
system/app/DsmsAPK
system/etc/permissions/privapp-permissions-com.samsung.android.dqagent.xml
system/etc/permissions/privapp-permissions-com.sec.android.diagmonagent.xml
system/etc/permissions/privapp-permissions-com.sec.android.soagent.xml
system/priv-app/DeviceQualityAgent36
system/priv-app/DiagMonAgent95
system/priv-app/SOAgent76
"

# HwModuleTest
SYSTEM_DEBLOAT+="
system/app/Cameralyzer
system/app/FactoryAirCommandManager
system/app/FactoryCameraFB
system/app/HMT
system/app/WlanTest
system/etc/default-permissions/default-permissions-com.sec.factory.cameralyzer.xml
system/etc/permissions/privapp-permissions-com.samsung.android.providers.factory.xml
system/etc/permissions/privapp-permissions-com.sec.facatfunction.xml
system/priv-app/FacAtFunction
system/priv-app/FactoryTestProvider
"

# Samsung PROCA certificate DB
SYSTEM_DEBLOAT+="
system/etc/proca.db
"

SYSTEM_EXT_DEBLOAT+="
framework/org.carconnectivity.android.digitalkey.rangingintent.jar
framework/org.carconnectivity.android.digitalkey.secureelement.jar
"

# Samsung Wallet
SYSTEM_DEBLOAT+="
system/etc/init/digitalkey_init_ble_tss2.rc
system/etc/permissions/org.carconnectivity.android.digitalkey.rangingintent.xml
system/etc/permissions/org.carconnectivity.android.digitalkey.secureelement.xml
system/etc/permissions/privapp-permissions-com.samsung.android.carkey.xml
system/etc/permissions/privapp-permissions-com.samsung.android.dkey.xml
system/etc/permissions/privapp-permissions-com.samsung.android.spayfw.xml
system/etc/permissions/signature-permissions-com.samsung.android.spay.xml
system/etc/permissions/signature-permissions-com.samsung.android.spayfw.xml
system/etc/sysconfig/digitalkey.xml
system/etc/sysconfig/preinstalled-packages-com.samsung.android.dkey.xml
system/etc/sysconfig/preinstalled-packages-com.samsung.android.spayfw.xml
system/priv-app/DigitalKey
system/priv-app/PaymentFramework
system/priv-app/SamsungCarKeyFw
"

# My Galaxy
SYSTEM_DEBLOAT+="
system/etc/permissions/privapp-permissions-com.mygalaxy.service.xml
system/etc/sysconfig/preinstalled-packages-com.mygalaxy.service.xml
system/priv-app/MyGalaxyService
"

# SettingsHelper
SYSTEM_DEBLOAT+="
system/etc/permissions/privapp-permissions-com.samsung.android.settingshelper.xml
system/etc/sysconfig/settingshelper.xml
system/priv-app/SHClient
"

# Recovery restoration script
VENDOR_DEBLOAT+="
recovery-from-boot.p
bin/install-recovery.sh
etc/init/vendor_flash_recovery.rc
"

# Apps debloat
PRODUCT_DEBLOAT+="
app/AssistantShell
app/BardShell
app/Chrome
app/Chrome64
app/DuoStub
app/Gmail2
app/Maps
app/YouTube
overlay/GmsConfigOverlaySearchSelector.apk
priv-app/AndroidAutoStub
priv-app/FamilyLinkParentalControls
priv-app/Messages
priv-app/SearchSelector
"

# Language packs
SYSTEM_DEBLOAT+="$(find "$WORK_DIR/system" -type d -name "*TTSVoice*" | sed "s|$WORK_DIR/system/||g")"

SYSTEM_DEBLOAT+="
system/app/ARCore
system/app/BBCAgent
system/app/BixbyWakeup
system/app/Cameralyzer
system/app/ClockPackage
system/app/DictDiotekForSec
system/app/DRParser
system/app/CarrierDefaultApp
system/app/ccinfo
system/app/ChromeCustomizations
system/app/EasymodeContactsWidget81
system/app/EasyOneHand3
system/app/GooglePrintRecommendationService
system/app/MinusOnePage
system/app/MoccaMobile
system/app/Netflix_activationCommon
system/app/Netflix_stub
system/app/Notes40
system/app/ParentalCare
system/app/PartnerBookmarksProvider
system/app/PrintSpooler
system/app/SafetyInformation
system/app/Stk
system/app/Stk2
system/app/SamsungCalendar
system/app/SmartSwitchAgent
system/app/SmartSwitchStub
system/app/Fast
system/app/FBAppManager_NS
system/app/KidsHome_Installer
system/app/MAPSAgent
system/app/MDMApp
system/app/PlayAutoInstallConfig
system/app/Rampart
system/app/SamsungPassAutofill_v1
system/app/SilentLog
system/app/SimAppDialog
system/app/Traceur
system/app/UniversalMDMClient
system/app/WifiGuider
system/etc/default-permissions/default-permissions-com.sec.spp.push.xml
system/etc/init/digitalkey_init_ble_tss2.rc
system/etc/init/samsung_pass_authenticator_service.rc
system/etc/permissions/authfw.xml
system/etc/permissions/com.samsung.feature.ipsgeofence.xml
system/etc/permissions/com.samsung.feature.samsungpositioning.xml
system/etc/permissions/org.carconnectivity.android.digitalkey.rangingintent.xml
system/etc/permissions/org.carconnectivity.android.digitalkey.secureelement.xml
system/etc/permissions/privapp-permissions-com.microsoft.skydrive.xml
system/etc/permissions/privapp-permissions-com.samsung.android.app.updatecenter.xml
system/etc/permissions/privapp-permissions-com.samsung.android.authfw.xml
system/etc/permissions/privapp-permissions-com.samsung.android.carkey.xml
system/etc/permissions/privapp-permissions-com.samsung.android.dkey.xml
system/etc/permissions/privapp-permissions-com.samsung.android.ipsgeofence.xml
system/etc/permissions/privapp-permissions-com.samsung.android.samsungpass.xml
system/etc/permissions/privapp-permissions-com.samsung.android.samsungpositioning.xml
system/etc/permissions/privapp-permissions-com.samsung.android.spayfw.xml
system/etc/permissions/privapp-permissions-com.samsung.oda.service.xml
system/etc/permissions/privapp-permissions-com.sec.android.diagmonagent.xml
system/etc/permissions/privapp-permissions-com.sec.android.soagent.xml
system/etc/permissions/privapp-permissions-com.sec.bcservice.xml
system/etc/permissions/privapp-permissions-com.sec.imslogger.xml
system/etc/permissions/privapp-permissions-com.sec.spp.push.xml
system/etc/permissions/privapp-permissions-com.skms.android.agent.xml
system/etc/permissions/privapp-permissions-com.wssyncmldm.xml
system/etc/permissions/privapp-permissions-meta.xml
system/etc/PF_TA
system/etc/sysconfig/digitalkey.xml
system/etc/sysconfig/meta-hiddenapi-package-allowlist.xml
system/etc/sysconfig/preinstalled-packages-com.samsung.android.dkey.xml
system/etc/sysconfig/preinstalled-packages-com.samsung.android.spayfw.xml
system/etc/sysconfig/samsungauthframework.xml
system/etc/sysconfig/samsungpassapp.xml
system/etc/sysconfig/samsungpushservice.xml
system/hidden/SmartTutor
system/preload/Facebook_stub_preload
system/priv-app/AppUpdateCenter
system/priv-app/AvatarPicker
system/priv-app/Bixby
system/priv-app/BixbyVisionFramework3.5
system/priv-app/BuiltInPrintService
system/priv-app/CIDManager
system/priv-app/EasySetup
system/priv-app/GameHome
system/priv-app/GameOptimizingService
system/priv-app/GameTools_Dream
system/priv-app/SamsungBilling
system/priv-app/SamsungExperienceService
system/priv-app/SmartSwitchAssistant
system/priv-app/SVoiceIME
system/priv-app/TalkbackSE
system/priv-app/AREmoji
system/priv-app/AREmojiEditor
system/priv-app/AvatarEmojiSticker
system/priv-app/AuthFramework
system/priv-app/BCService
system/priv-app/CpAgent
system/priv-app/DiagMonAgent95
system/priv-app/DigitalKey
system/priv-app/EnhancedAttestationAgent
system/priv-app/FBInstaller_NS
system/priv-app/FBServices
system/priv-app/FotaAgent
system/priv-app/ImsLogger
system/priv-app/IpsGeofence
system/priv-app/OdaService
system/priv-app/OMCAgent5
system/priv-app/OneDrive_Samsung_v3
system/priv-app/PaymentFramework
system/priv-app/SamsungCarKeyFw
system/priv-app/SamsungPass
system/priv-app/SamsungPositioning
system/priv-app/SKMSAgent
system/priv-app/SOAgent76
system/priv-app/SPPPushClient
system/priv-app/StickerFaceARAvatar
system/priv-app/YourPhone_P1_5
"

PRISM_DEBLOAT+="
app
etc
HWRDB
preload
priv-app
sipdb
"

OPTICS_DEBLOAT+="
configs
"

# eSIM
if $SOURCE_IS_ESIM_SUPPORTED; then
    if ! $TARGET_IS_ESIM_SUPPORTED; then
        SYSTEM_DEBLOAT+="
        system/etc/permissions/privapp-permissions-com.samsung.android.app.esimkeystring.xml
        system/etc/permissions/privapp-permissions-com.samsung.euicc.mep.xml
        system/etc/sysconfig/preinstalled-packages-com.samsung.android.app.esimkeystring.xml
        system/etc/sysconfig/preinstalled-packages-com.samsung.euicc.xml
        system/priv-app/EsimKeyString
        system/priv-app/EsimClient
        system/priv-app/EuiccService
        "
    fi
fi
