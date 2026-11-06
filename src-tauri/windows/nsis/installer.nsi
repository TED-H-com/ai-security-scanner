; Vendored from Tauri CLI's NSIS template for reproducible Windows packaging.
; Upstream tag: tauri-cli-v2.12.4
; Upstream commit: 993038c49185307dfc895ab7657d77ca0d5ed7c7
; Upstream URL: https://raw.githubusercontent.com/tauri-apps/tauri/tauri-cli-v2.12.4/crates/tauri-bundler/src/bundle/windows/nsis/installer.nsi
; Upstream SHA-256: d00089d3b1a2c4a30d7b6e098079100cb8f25e980f84d4515aca4597b95e967d
; Upstream license: Apache-2.0 OR MIT
; Local patch: version-neutral stale-registration and same-version repair,
; data-preserving upgrade overlays, synchronous copied-uninstaller execution,
; exact private runtime-cache seeding, fixed Windows-prerequisite preparation with
; durable restart/resume state, and a bilingual three-choice uninstall
; delegated to the fixed product CLI with bounded, visible coordinator records
; and exact registration postconditions.
; The release validator reverses these reviewed hunks and verifies both
; complete-file SHA-256 values.

Unicode true
ManifestDPIAware true
; Add in `dpiAwareness` `PerMonitorV2` to manifest for Windows 10 1607+ (note this should not affect lower versions since they should be able to ignore this and pick up `dpiAware` `true` set by `ManifestDPIAware true`)
; Currently undocumented on NSIS's website but is in the Docs folder of source tree, see
; https://github.com/kichik/nsis/blob/5fc0b87b819a9eec006df4967d08e522ddd651c9/Docs/src/attributes.but#L286-L300
; https://github.com/tauri-apps/tauri/pull/10106
ManifestDPIAwareness PerMonitorV2

!if "{{compression}}" == "none"
  SetCompress off
!else
  ; Set the compression algorithm. We default to LZMA.
  SetCompressor /SOLID "{{compression}}"
!endif

; Keep above !include to stay ahead of any plugin command
; see https://github.com/tauri-apps/tauri/pull/15422#discussion_r3289239624
{{#if signed_plugins_path}}
!addplugindir "{{signed_plugins_path}}"
{{/if}}

!include MUI2.nsh
!include FileFunc.nsh
!include x64.nsh
!include WordFunc.nsh
!include "utils.nsh"
!include "FileAssociation.nsh"
!include "Win\COM.nsh"
!include "Win\Propkey.nsh"
!include "Win\RestartManager.nsh"
!include "StrFunc.nsh"
${StrCase}
${StrLoc}
${UnStrLoc}

{{#if installer_hooks}}
!include "{{installer_hooks}}"
{{/if}}

!define WEBVIEW2APPGUID "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"

!define MANUFACTURER "{{manufacturer}}"
!define PRODUCTNAME "{{product_name}}"
!define VERSION "{{version}}"
!define VERSIONWITHBUILD "{{version_with_build}}"
!define HOMEPAGE "{{homepage}}"
!define INSTALLMODE "{{install_mode}}"
!define LICENSE "{{license}}"
!define INSTALLERICON "{{installer_icon}}"
!define SIDEBARIMAGE "{{sidebar_image}}"
!define HEADERIMAGE "{{header_image}}"
!define UNINSTALLERICON "{{uninstaller_icon}}"
!define UNINSTALLERHEADERIMAGE "{{uninstaller_header_image}}"
!define MAINBINARYNAME "{{main_binary_name}}"
!define MAINBINARYSRCPATH "{{main_binary_path}}"
!define BUNDLEID "{{bundle_id}}"
!define COPYRIGHT "{{copyright}}"
!define OUTFILE "{{out_file}}"
!define ARCH "{{arch}}"
!define ADDITIONALPLUGINSPATH "{{additional_plugins_path}}"
!define ALLOWDOWNGRADES "{{allow_downgrades}}"
!define DISPLAYLANGUAGESELECTOR "{{display_language_selector}}"
!define INSTALLWEBVIEW2MODE "{{install_webview2_mode}}"
!define WEBVIEW2INSTALLERARGS "{{webview2_installer_args}}"
!define WEBVIEW2BOOTSTRAPPERPATH "{{webview2_bootstrapper_path}}"
!define WEBVIEW2INSTALLERPATH "{{webview2_installer_path}}"
!define MINIMUMWEBVIEW2VERSION "{{minimum_webview2_version}}"
!define UNINSTKEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCTNAME}"
!define MANUKEY "Software\${MANUFACTURER}"
!define MANUPRODUCTKEY "${MANUKEY}\${PRODUCTNAME}"
!define UNINSTALLERSIGNCOMMAND "{{uninstaller_sign_cmd}}"
!define ESTIMATEDSIZE "{{estimated_size}}"
!define STARTMENUFOLDER "{{start_menu_folder}}"

Var PassiveMode
Var UpdateMode
Var NoShortcutMode
Var WixMode
Var OldMainBinaryName
Var RegistrationOverlayMode

Name "${PRODUCTNAME}"
BrandingText "${COPYRIGHT}"
OutFile "${OUTFILE}"

; We don't actually use this value as default install path,
; it's just for nsis to append the product name folder in the directory selector
; https://nsis.sourceforge.io/Reference/InstallDir
!define PLACEHOLDER_INSTALL_DIR "placeholder\${PRODUCTNAME}"
InstallDir "${PLACEHOLDER_INSTALL_DIR}"

VIProductVersion "${VERSIONWITHBUILD}"
VIAddVersionKey "ProductName" "${PRODUCTNAME}"
VIAddVersionKey "FileDescription" "${PRODUCTNAME}"
VIAddVersionKey "LegalCopyright" "${COPYRIGHT}"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "ProductVersion" "${VERSION}"

# additional plugins
!addplugindir "${ADDITIONALPLUGINSPATH}"

; Uninstaller signing command
!if "${UNINSTALLERSIGNCOMMAND}" != ""
  !uninstfinalize '${UNINSTALLERSIGNCOMMAND}'
!endif

; Handle install mode, `perUser`, `perMachine` or `both`
!if "${INSTALLMODE}" == "perMachine"
  RequestExecutionLevel admin
!endif

!if "${INSTALLMODE}" == "currentUser"
  RequestExecutionLevel user
!endif

!if "${INSTALLMODE}" == "both"
  !define MULTIUSER_MUI
  !define MULTIUSER_INSTALLMODE_INSTDIR "${PRODUCTNAME}"
  !define MULTIUSER_INSTALLMODE_COMMANDLINE
  !if "${ARCH}" == "x64"
    !define MULTIUSER_USE_PROGRAMFILES64
  !else if "${ARCH}" == "arm64"
    !define MULTIUSER_USE_PROGRAMFILES64
  !endif
  !define MULTIUSER_INSTALLMODE_DEFAULT_REGISTRY_KEY "${UNINSTKEY}"
  !define MULTIUSER_INSTALLMODE_DEFAULT_REGISTRY_VALUENAME "CurrentUser"
  !define MULTIUSER_INSTALLMODEPAGE_SHOWUSERNAME
  !define MULTIUSER_INSTALLMODE_FUNCTION RestorePreviousInstallLocation
  !define MULTIUSER_EXECUTIONLEVEL Highest
  !include MultiUser.nsh
!endif

; Installer icon
!if "${INSTALLERICON}" != ""
  !define MUI_ICON "${INSTALLERICON}"
!endif

; Installer sidebar image
!if "${SIDEBARIMAGE}" != ""
  !define MUI_WELCOMEFINISHPAGE_BITMAP "${SIDEBARIMAGE}"
!endif

; Enable header images for installer and uninstaller pages when either image is configured.
!if "${HEADERIMAGE}" != ""
  !define MUI_HEADERIMAGE
!else if "${UNINSTALLERHEADERIMAGE}" != ""
  !define MUI_HEADERIMAGE
!endif

; Installer header image
!if "${HEADERIMAGE}" != ""
  !define MUI_HEADERIMAGE_BITMAP "${HEADERIMAGE}"
!endif

; Uninstaller header image
!if "${UNINSTALLERHEADERIMAGE}" != ""
  !define MUI_HEADERIMAGE_UNBITMAP "${UNINSTALLERHEADERIMAGE}"
!endif

; Uninstaller icon
!if "${UNINSTALLERICON}" != ""
  !define MUI_UNICON "${UNINSTALLERICON}"
!endif

; Define registry key to store installer language
!define MUI_LANGDLL_REGISTRY_ROOT "HKCU"
!define MUI_LANGDLL_REGISTRY_KEY "${MANUPRODUCTKEY}"
!define MUI_LANGDLL_REGISTRY_VALUENAME "Installer Language"

; Installer pages, must be ordered as they appear
; 1. Welcome Page
!define MUI_PAGE_CUSTOMFUNCTION_PRE SkipIfPassive
!insertmacro MUI_PAGE_WELCOME

; 2. License Page (if defined)
!if "${LICENSE}" != ""
  !define MUI_PAGE_CUSTOMFUNCTION_PRE SkipIfPassive
  !insertmacro MUI_PAGE_LICENSE "${LICENSE}"
!endif

; 3. Install mode (if it is set to `both`)
!if "${INSTALLMODE}" == "both"
  !define MUI_PAGE_CUSTOMFUNCTION_PRE SkipIfPassive
  !insertmacro MULTIUSER_PAGE_INSTALLMODE
!endif

; 4. Custom page to ask user if he wants to reinstall/uninstall
;    only if a previous installation was detected
Var ReinstallPageCheck
Page custom PageReinstall PageLeaveReinstall

; Find a previous WiX installation and set $R6 to its uninstall registry key, or to "" if none.
;
; A WiX installer stores the installation info in registry
; using a UUID and so we have to loop through all keys under
; `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
; and check if `DisplayName` and `Publisher` keys match ${PRODUCTNAME} and ${MANUFACTURER}
;
; This has a potential issue that there maybe another installation that matches
; our ${PRODUCTNAME} and ${MANUFACTURER} but wasn't installed by our WiX installer,
; however, this should be fine since the user will have to confirm the uninstallation
; and they can chose to abort it if doesn't make sense.
Function FindWixInstall
  StrCpy $R6 ""
  StrCpy $0 0
  wix_loop:
    EnumRegKey $1 HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" $0
    StrCmp $1 "" wix_loop_done ; Exit loop if there is no more keys to loop on
    IntOp $0 $0 + 1
    ReadRegStr $R0 HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$1" "DisplayName"
    ReadRegStr $R1 HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$1" "Publisher"
    StrCmp "$R0$R1" "${PRODUCTNAME}${MANUFACTURER}" 0 wix_loop
    ReadRegStr $R0 HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$1" "UninstallString"
    ${StrCase} $R1 $R0 "L"
    ${StrLoc} $R0 $R1 "msiexec" ">"
    StrCmp $R0 0 0 wix_loop_done
    StrCpy $R6 "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$1"
  wix_loop_done:
FunctionEnd

Function PageReinstall
  ; .onInit proves an exact current-user product registration before choosing
  ; this path. Stale registrations, same-version repairs, and upgrades replace
  ; only the candidate's known files and registration in place. They never run
  ; an absent or older uninstaller and never touch runtime, cases, or app data.
  ${If} $RegistrationOverlayMode <> 0
    Abort
  ${EndIf}

  ; Uninstall previous WiX installation if exists.
  Call FindWixInstall
  ${If} $R6 != ""
    StrCpy $WixMode 1
    Goto compare_version
  ${EndIf}

  ; Check if there is an existing installation, if not, abort the reinstall page
  ReadRegStr $R0 SHCTX "${UNINSTKEY}" ""
  ReadRegStr $R1 SHCTX "${UNINSTKEY}" "UninstallString"
  ${IfThen} "$R0$R1" == "" ${|} Abort ${|}

  ; Compare this installar version with the existing installation
  ; and modify the messages presented to the user accordingly
  compare_version:
  StrCpy $R4 "$(older)"
  ${If} $WixMode = 1
    ReadRegStr $R0 HKLM "$R6" "DisplayVersion"
  ${Else}
    ReadRegStr $R0 SHCTX "${UNINSTKEY}" "DisplayVersion"
  ${EndIf}
  ${IfThen} $R0 == "" ${|} StrCpy $R4 "$(unknown)" ${|}

  nsis_tauri_utils::SemverCompare "${VERSION}" $R0
  Pop $R0

  ; Read the install choice header through $R5 so a custom language file that only
  ; defines the misspelled `choowHowToInstall` still shows its own text
  ; TODO: remove the `choowHowToInstall` fallback in a future major version
  StrCpy $R5 "$(chooseHowToInstall)"
  ${IfThen} $R5 == "" ${|} StrCpy $R5 "$(choowHowToInstall)" ${|}

  ; Reinstalling the same version
  ${If} $R0 = 0
    StrCpy $R1 "$(alreadyInstalledLong)"
    StrCpy $R2 "$(addOrReinstall)"
    StrCpy $R3 "$(uninstallApp)"
    !insertmacro MUI_HEADER_TEXT "$(alreadyInstalled)" "$(chooseMaintenanceOption)"
  ; Upgrading
  ${ElseIf} $R0 = 1
    StrCpy $R1 "$(olderOrUnknownVersionInstalled)"
    StrCpy $R2 "$(uninstallBeforeInstalling)"
    StrCpy $R3 "$(dontUninstall)"
    !insertmacro MUI_HEADER_TEXT "$(alreadyInstalled)" "$R5"
  ; Downgrading
  ${ElseIf} $R0 = -1
    StrCpy $R1 "$(newerVersionInstalled)"
    StrCpy $R2 "$(uninstallBeforeInstalling)"
    !if "${ALLOWDOWNGRADES}" == "true"
      StrCpy $R3 "$(dontUninstall)"
    !else
      StrCpy $R3 "$(dontUninstallDowngrade)"
    !endif
    !insertmacro MUI_HEADER_TEXT "$(alreadyInstalled)" "$R5"
  ${Else}
    Abort
  ${EndIf}

  ; Skip showing the page if passive
  ;
  ; Note that we don't call this earlier at the beginning
  ; of this function because we need to populate some variables
  ; related to current installed version if detected and whether
  ; we are downgrading or not.
  ${If} $PassiveMode = 1
    Call PageLeaveReinstall
  ${Else}
    nsDialogs::Create 1018
    Pop $R4
    ${IfThen} $(^RTL) = 1 ${|} nsDialogs::SetRTL $(^RTL) ${|}

    ${NSD_CreateLabel} 0 0 100% 24u $R1
    Pop $R1

    ${NSD_CreateRadioButton} 30u 50u -30u 8u $R2
    Pop $R2
    ${NSD_OnClick} $R2 PageReinstallUpdateSelection

    ${NSD_CreateRadioButton} 30u 70u -30u 8u $R3
    Pop $R3
    ; Disable this radio button if downgrading and downgrades are disabled
    !if "${ALLOWDOWNGRADES}" == "false"
      ${IfThen} $R0 = -1 ${|} EnableWindow $R3 0 ${|}
    !endif
    ${NSD_OnClick} $R3 PageReinstallUpdateSelection

    ; Check the first radio button if this the first time
    ; we enter this page or if the second button wasn't
    ; selected the last time we were on this page
    ${If} $ReinstallPageCheck <> 2
      SendMessage $R2 ${BM_SETCHECK} ${BST_CHECKED} 0
    ${Else}
      SendMessage $R3 ${BM_SETCHECK} ${BST_CHECKED} 0
    ${EndIf}

    ${NSD_SetFocus} $R2
    nsDialogs::Show
  ${EndIf}
FunctionEnd
Function PageReinstallUpdateSelection
  ${NSD_GetState} $R2 $R1
  ${If} $R1 == ${BST_CHECKED}
    StrCpy $ReinstallPageCheck 1
  ${Else}
    StrCpy $ReinstallPageCheck 2
  ${EndIf}
FunctionEnd
Function PageLeaveReinstall
  ; Passive and silent setup have no usable radio-button HWND. Make their
  ; normal upgrade behavior explicit: select the first (uninstall old version)
  ; choice. Tauri updater mode remains the separate no-uninstall path below.
  ${If} $PassiveMode = 1
    StrCpy $R1 1
  ${ElseIf} ${Silent}
    StrCpy $R1 1
  ${Else}
    ${NSD_GetState} $R2 $R1
  ${EndIf}

  ; If migrating from Wix, always uninstall
  ${If} $WixMode = 1
    Goto reinst_uninstall
  ${EndIf}

  ; In update mode, always proceeds without uninstalling
  ${If} $UpdateMode = 1
    Goto reinst_done
  ${EndIf}

  ; $R0 holds whether same(0)/upgrading(1)/downgrading(-1) version
  ; $R1 holds the radio buttons state:
  ;   1 => first choice was selected
  ;   0 => second choice was selected
  ${If} $R0 = 0 ; Same version, proceed
    ${If} $R1 = 1              ; User chose to add/reinstall
      Goto reinst_done
    ${Else}                    ; User chose to uninstall
      Goto reinst_uninstall
    ${EndIf}
  ${ElseIf} $R0 = 1 ; Upgrading
    ${If} $R1 = 1              ; User chose to uninstall
      Goto reinst_uninstall
    ${Else}
      Goto reinst_done         ; User chose NOT to uninstall
    ${EndIf}
  ${ElseIf} $R0 = -1 ; Downgrading
    ${If} $R1 = 1              ; User chose to uninstall
      Goto reinst_uninstall
    ${Else}
      Goto reinst_done         ; User chose NOT to uninstall
    ${EndIf}
  ${EndIf}

  reinst_uninstall:
    HideWindow
    ClearErrors

    ${If} $WixMode = 1
      ReadRegStr $R1 HKLM "$R6" "UninstallString"
      ExecWait '$R1' $0
    ${Else}
      ReadRegStr $4 SHCTX "${MANUPRODUCTKEY}" ""
      ReadRegStr $R1 SHCTX "${UNINSTKEY}" "UninstallString"
      StrCpy $R3 '$\"$4\uninstall.exe$\"'
      ${If} $4 == ""
        StrCpy $0 2
      ${ElseIf} $R1 != $R3
        ; Never execute a command taken from an inconsistent registration.
        StrCpy $0 2
      ${Else}
        ${IfNot} ${FileExists} "$4\uninstall.exe"
          StrCpy $0 2
        ${Else}
          ; NSIS uninstallers normally launch a temporary child and return before
          ; that child finishes. _?= makes execution synchronous, but also runs
          ; the named executable in place. Copy the exact registered uninstaller
          ; into this installer's private temp directory first so the original can
          ; delete itself and its install directory before ExecWait returns.
          InitPluginsDir
          StrCpy $R2 "$PLUGINSDIR\ai-security-scanner-previous-uninstaller.exe"
          ClearErrors
          CopyFiles /SILENT "$4\uninstall.exe" "$R2"
          ${If} ${Errors}
            StrCpy $0 2
          ${Else}
            ${IfNot} ${FileExists} "$R2"
              StrCpy $0 2
            ${Else}
              StrCpy $R1 '$\"$R2$\"'
              ${IfThen} $UpdateMode = 1 ${|} StrCpy $R1 "$R1 /UPDATE" ${|} ; append /UPDATE
              ${If} $PassiveMode = 1
                StrCpy $R1 "$R1 /P" ; preserve passive mode in the old uninstaller
              ${ElseIf} ${Silent}
                StrCpy $R1 "$R1 /S" ; preserve silent mode in the old uninstaller
              ${EndIf}
              StrCpy $R1 "$R1 _?=$4" ; _?= must be the final argument
              ClearErrors
              ExecWait '$R1' $0
              ${If} ${Errors}
                StrCpy $0 2
              ${EndIf}
            ${EndIf}
          ${EndIf}
          Delete "$R2"
        ${EndIf}
      ${EndIf}
    ${EndIf}

    BringToFront

    ${IfThen} ${Errors} ${|} StrCpy $0 2 ${|} ; ExecWait failed, set fake exit code

    ${If} $0 <> 0
    ${OrIf} ${FileExists} "$INSTDIR\${MAINBINARYNAME}.exe"
      ; User cancelled wix uninstaller? return to select un/reinstall page
      ${If} $WixMode = 1
      ${AndIf} $0 = 1602
        Abort
      ${EndIf}

      ; User cancelled NSIS uninstaller? return to select un/reinstall page
      ${If} $0 = 1
        Abort
      ${EndIf}

      ; Other errors? show generic error message and return to select un/reinstall page
      MessageBox MB_ICONEXCLAMATION "$(unableToUninstall)"
      Abort
    ${EndIf}

    ; The NSIS uninstaller was run in place (`_?=`), so it cannot delete itself
    ; and the install directory, clean them up here once the uninstall succeeded
    ; https://nsis.sourceforge.io/Docs/Chapter3.html#:~:text=path%20contains%20spaces.-,3.2.3%20Examples,-installer.exe%20/NCRC
    ${If} $WixMode = 0
    ${AndIf} $4 != ""
      Delete "$4\uninstall.exe"
      RMDir "$4"
    ${EndIf}
  reinst_done:
FunctionEnd

; 5. Choose install directory page
!define MUI_PAGE_CUSTOMFUNCTION_PRE SkipDirectoryIfRepairOrPassive
!insertmacro MUI_PAGE_DIRECTORY

; 6. Start menu shortcut page
Var AppStartMenuFolder
!if "${STARTMENUFOLDER}" != ""
  !define MUI_PAGE_CUSTOMFUNCTION_PRE SkipIfPassive
  !define MUI_STARTMENUPAGE_DEFAULTFOLDER "${STARTMENUFOLDER}"
!else
  !define MUI_PAGE_CUSTOMFUNCTION_PRE Skip
!endif
!insertmacro MUI_PAGE_STARTMENU Application $AppStartMenuFolder

; 7. Installation page
!insertmacro MUI_PAGE_INSTFILES

; 8. Finish page
;
; Don't auto jump to finish page after installation page,
; because the installation page has useful info that can be used debug any issues with the installer.
!define MUI_FINISHPAGE_NOAUTOCLOSE
; Use show readme button in the finish page as a button create a desktop shortcut
!define MUI_FINISHPAGE_SHOWREADME
!define MUI_FINISHPAGE_SHOWREADME_TEXT "$(createDesktop)"
!define MUI_FINISHPAGE_SHOWREADME_FUNCTION CreateOrUpdateDesktopShortcut
; Show run app after installation.
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_FUNCTION RunMainBinary
!define MUI_PAGE_CUSTOMFUNCTION_PRE SkipIfPassive
!insertmacro MUI_PAGE_FINISH

Function RunMainBinary
  nsis_tauri_utils::RunAsUser "$INSTDIR\${MAINBINARYNAME}.exe" ""
FunctionEnd

; Uninstaller Pages
; 1. Choose exactly what this uninstall removes. Silent/passive uninstall and
;    updater replacement deliberately keep the default app-only choice.
Var UninstallChoice
Var UninstallAppOnlyRadio
Var UninstallScanToolsRadio
Var UninstallAllDataRadio
Var UninstallCoordinatorResult
Var UninstallCoordinatorOutput
Var UninstallReceiptPath
Var UninstallPartialOutcome
Var UninstallPostconditionFailed
Var UninstallInstallPathRegistration
Var UninstallInstallPathRegistrationPresent
Var UninstallInstallerLanguage
Var UninstallInstallerLanguagePresent

UninstPage custom un.UninstallChoicePage un.UninstallChoiceLeave

; LoadLanguageFile defines ${LANG_TRADCHINESE} later, when Tauri expands the
; configured MUI_LANGUAGE entries. These custom-page functions are compiled
; before that point, so use the stable Windows/NSIS Traditional Chinese LCID
; here instead of referencing a not-yet-defined preprocessor symbol.
!define PRODUCT_LANG_TRADCHINESE 1028

Function un.UninstallChoicePage
  ${If} $PassiveMode = 1
  ${OrIf} $UpdateMode = 1
  ${OrIf} ${Silent}
    Abort
  ${EndIf}

  ${If} $LANGUAGE == ${PRODUCT_LANG_TRADCHINESE}
    !insertmacro MUI_HEADER_TEXT "選擇要移除的內容" "未明確選擇刪除的資料都會保留。"
  ${Else}
    !insertmacro MUI_HEADER_TEXT "Choose what to remove" "Anything you do not explicitly choose to delete is preserved."
  ${EndIf}

  nsDialogs::Create 1018
  Pop $0
  ${If} $0 == error
    Abort
  ${EndIf}
  ${IfThen} $(^RTL) = 1 ${|} nsDialogs::SetRTL $(^RTL) ${|}

  ${If} $LANGUAGE == ${PRODUCT_LANG_TRADCHINESE}
    ${NSD_CreateRadioButton} 0 4u 100% 14u "僅移除應用程式（預設）"
    Pop $UninstallAppOnlyRadio
    ${NSD_CreateLabel} 16u 20u -16u 22u "保留專案、證據、匯出、偏好設定、簽章身分與掃描工具。"
    Pop $0

    ${NSD_CreateRadioButton} 0 48u 100% 14u "移除應用程式與掃描工具；保留專案"
    Pop $UninstallScanToolsRadio
    ${NSD_CreateLabel} 16u 64u -16u 28u "保留專案、證據、匯出、偏好設定與簽章身分；所有權不明的項目會保留。"
    Pop $0

    ${NSD_CreateRadioButton} 0 98u 100% 14u "移除應用程式與所有 ai-security-scanner 資料"
    Pop $UninstallAllDataRadio
    ${NSD_CreateLabel} 16u 114u -16u 28u "下一步再次確認後，永久移除本產品能安全辨識的資料。"
    Pop $0
  ${Else}
    ${NSD_CreateRadioButton} 0 4u 100% 14u "Remove the app only (default)"
    Pop $UninstallAppOnlyRadio
    ${NSD_CreateLabel} 16u 20u -16u 22u "Keeps projects, evidence, exports, preferences, signing identity, and scan tools."
    Pop $0

    ${NSD_CreateRadioButton} 0 48u 100% 14u "Remove the app and scan tools; keep my projects"
    Pop $UninstallScanToolsRadio
    ${NSD_CreateLabel} 16u 64u -16u 28u "Keeps projects, evidence, exports, preferences, and signing identity. Ambiguous items are retained."
    Pop $0

    ${NSD_CreateRadioButton} 0 98u 100% 14u "Remove the app and all ai-security-scanner data"
    Pop $UninstallAllDataRadio
    ${NSD_CreateLabel} 16u 114u -16u 28u "Permanently removes data this app can safely identify after one more confirmation."
    Pop $0
  ${EndIf}

  ${If} $UninstallChoice == "scan-tools"
    ${NSD_Check} $UninstallScanToolsRadio
  ${ElseIf} $UninstallChoice == "all-data"
    ${NSD_Check} $UninstallAllDataRadio
  ${Else}
    ${NSD_Check} $UninstallAppOnlyRadio
  ${EndIf}

  GetDlgItem $0 $HWNDPARENT 1
  ${If} $LANGUAGE == ${PRODUCT_LANG_TRADCHINESE}
    SendMessage $0 ${WM_SETTEXT} 0 "STR:解除安裝"
  ${Else}
    SendMessage $0 ${WM_SETTEXT} 0 "STR:Uninstall"
  ${EndIf}
  nsDialogs::Show
FunctionEnd

Function un.UninstallChoiceLeave
  ${NSD_GetState} $UninstallScanToolsRadio $0
  ${If} $0 == ${BST_CHECKED}
    StrCpy $UninstallChoice "scan-tools"
    Return
  ${EndIf}

  ${NSD_GetState} $UninstallAllDataRadio $0
  ${If} $0 == ${BST_CHECKED}
    ${If} $LANGUAGE == ${PRODUCT_LANG_TRADCHINESE}
      MessageBox MB_ICONSTOP|MB_YESNO|MB_DEFBUTTON2 "這會永久移除專案、證據、匯出、偏好設定、簽章身分，以及本產品能安全辨識的掃描工具，且無法復原。若要先匯出備份，請選擇「否」返回。確定要移除所有 ai-security-scanner 資料嗎？" IDYES un_all_data_confirmed
    ${Else}
      MessageBox MB_ICONSTOP|MB_YESNO|MB_DEFBUTTON2 "This permanently removes projects, evidence, exports, preferences, signing identity, and scan tools this app can safely identify. It cannot be undone. Choose No to return and export a backup first. Remove all ai-security-scanner data?" IDYES un_all_data_confirmed
    ${EndIf}
    Abort
    un_all_data_confirmed:
    StrCpy $UninstallChoice "all-data"
    Return
  ${EndIf}

  StrCpy $UninstallChoice "app-only"
FunctionEnd

; 2. Uninstalling Page
!insertmacro MUI_UNPAGE_INSTFILES

;Languages
; PageReinstall reads the misspelled `choowHowToInstall` as a fallback, and makensis warns
; about a language string that is read but never set, so default it to an empty string for
; every language. This runs before the language files are included, so a custom language
; file that only defines the old spelling overrides the default and the fallback shows its
; text. `0` as the language id means the language inserted right above.
; TODO: remove the `choowHowToInstall` fallback in a future major version
{{#each languages}}
!insertmacro MUI_LANGUAGE "{{this}}"
LangString choowHowToInstall 0 ""
{{/each}}
!insertmacro MUI_RESERVEFILE_LANGDLL
{{#each language_files}}
  !include "{{this}}"
{{/each}}

; BEGIN AI SECURITY SCANNER BILINGUAL PRODUCT STRINGS
; Product-specific messages are deliberately available in every configured
; installer language. WSL/runtime terminology stays out of these first-layer
; messages and remains available only in the install log/Technical details.
LangString windowsPrerequisiteChecking ${LANG_ENGLISH} "Preparing the Windows support used by local scan tools..."
LangString windowsPrerequisiteChecking ${LANG_TRADCHINESE} "正在準備本機掃描工具需要的 Windows 支援..."
LangString windowsPrerequisiteReady ${LANG_ENGLISH} "Windows support for local scan tools is ready."
LangString windowsPrerequisiteReady ${LANG_TRADCHINESE} "本機掃描工具需要的 Windows 支援已準備完成。"
LangString windowsPrerequisiteRestart ${LANG_ENGLISH} "Windows needs a restart before local scan tools can finish preparing. The app will continue automatically the next time it opens."
LangString windowsPrerequisiteRestart ${LANG_TRADCHINESE} "Windows 需要重新啟動，才能完成本機掃描工具的準備。下次開啟應用程式時會自動繼續。"
LangString windowsPrerequisiteRetry ${LANG_ENGLISH} "Windows support could not finish preparing. The app is installed and can open; local scan tools will retry automatically."
LangString windowsPrerequisiteRetry ${LANG_TRADCHINESE} "Windows 支援尚未準備完成。應用程式已安裝並可正常開啟；本機掃描工具會自動重試。"

; Uninstall messages appear only when an operation is partial or cannot safely
; continue. Scanner/runtime terminology stays out of the primary choice page.
LangString unCoordinatorRecordLabel ${LANG_ENGLISH} "Privacy-safe removal details:"
LangString unCoordinatorRecordLabel ${LANG_TRADCHINESE} "不含敏感資訊的移除細節："
LangString unCoordinatorStartFailed ${LANG_ENGLISH} "The app could not prepare removal. Nothing was deleted. Close ai-security-scanner and try again."
LangString unCoordinatorStartFailed ${LANG_TRADCHINESE} "應用程式無法準備移除，因此尚未刪除任何內容。請關閉 ai-security-scanner 後再試一次。"
LangString unCoordinatorTimedOut ${LANG_ENGLISH} "Cleanup is taking longer than expected. The app was kept so you can retry safely; some selected cleanup may already be complete."
LangString unCoordinatorTimedOut ${LANG_TRADCHINESE} "清理時間超出預期。應用程式已保留，您可以安全地重試；部分所選內容可能已經清理完成。"
LangString unCoordinatorInvalidRecord ${LANG_ENGLISH} "The app could not confirm what was removed, so it kept the app for a safe retry."
LangString unCoordinatorInvalidRecord ${LANG_TRADCHINESE} "應用程式無法確認已移除的內容，因此保留應用程式，讓您可以安全地重試。"
LangString unCoordinatorFatal ${LANG_ENGLISH} "The app could not safely finish preparing removal. The app and its data were kept."
LangString unCoordinatorFatal ${LANG_TRADCHINESE} "應用程式無法安全地完成移除準備，因此應用程式與資料都已保留。"
LangString unCoordinatorRetained ${LANG_ENGLISH} "Some items could not be safely identified or removed, so they were left untouched. The app will still be removed."
LangString unCoordinatorRetained ${LANG_TRADCHINESE} "部分項目無法安全辨識或移除，因此保持原狀。應用程式仍會移除。"
LangString unCoordinatorReceiptSaved ${LANG_ENGLISH} "A short, privacy-safe removal record was saved here:"
LangString unCoordinatorReceiptSaved ${LANG_TRADCHINESE} "簡短且不含敏感資訊的移除紀錄已儲存於："
LangString unCoordinatorReceiptFailed ${LANG_ENGLISH} "Windows could not save the short removal record. The same details remain visible above."
LangString unCoordinatorReceiptFailed ${LANG_TRADCHINESE} "Windows 無法儲存簡短的移除紀錄；上方仍會顯示相同細節。"
LangString unCoordinatorContactNotStopped ${LANG_ENGLISH} "A scan is still contacting a target. Choose Retry to stop it again, or Cancel to keep the app and data installed."
LangString unCoordinatorContactNotStopped ${LANG_TRADCHINESE} "掃描仍在連線至目標。請選擇「重試」再次停止掃描，或選擇「取消」保留應用程式與資料。"
LangString unCoordinatorContactRetained ${LANG_ENGLISH} "The scan could not be stopped. The app and its data were kept."
LangString unCoordinatorContactRetained ${LANG_TRADCHINESE} "掃描無法停止，因此應用程式與資料都已保留。"
LangString unPostconditionPartial ${LANG_ENGLISH} "Windows could not remove every app file or registration. Anything it could not confirm was left untouched. Restart Windows, then try uninstalling again."
LangString unPostconditionPartial ${LANG_TRADCHINESE} "Windows 無法移除所有應用程式檔案或登錄資料。無法確認的內容都保持原狀。請重新啟動 Windows，然後再次解除安裝。"
; END AI SECURITY SCANNER BILINGUAL PRODUCT STRINGS

Function SeedManagedRuntimePrivateCache
  ; Copy only the current installer's already-extracted, manifest-verified
  ; runtime payload into the product's exact private version namespace. The
  ; hidden CLI owns the fixed LocalAppData and sibling bundle resolution; this
  ; installer supplies no path, action, executable, or other mutable input.
  ; manager.install verifies every source byte and commits through a private
  ; staging directory without executing Podman, WSL, or another runtime helper.
  ${IfNot} ${FileExists} "$INSTDIR\ai-security-scanner-cli.exe"
    Return
  ${EndIf}

  ; Cache preparation is useful recovery redundancy, never an application
  ; installation gate. Any missing helper, timeout, nonzero exit, malformed
  ; envelope, or rejected payload leaves the installed shell/resources intact;
  ; the desktop will retry ordinary verified preparation when needed.
  nsExec::ExecToStack /TIMEOUT=180000 '"$INSTDIR\ai-security-scanner-cli.exe" --json windows-installer-runtime-cache'
  Pop $R0
  Pop $R1
  ${If} $R0 = 0
  ${AndIf} $R1 == '{"schema_version":"ai-security-scanner.windows-installer-runtime-cache/v1","result_class":"seeded","exit_code":0,"terminal":"complete"}'
    Return
  ${EndIf}
  ${If} $R0 = 30
  ${AndIf} $R1 == '{"schema_version":"ai-security-scanner.windows-installer-runtime-cache/v1","result_class":"unavailable","exit_code":30,"terminal":"complete"}'
    Return
  ${EndIf}
FunctionEnd

Function RunWindowsInstallerPrerequisiteCoordinator
  ; Application binaries and registration already exist when this runs. The
  ; fixed CLI command accepts no action, executable, argument, path, target, or
  ; webview input. It derives the read-only Windows check and, only when needed,
  ; one product-defined Microsoft servicing action inside the trusted backend.
  ; Persist one non-authoritative receipt before the side effect so an
  ; interrupted install records that preparation may need to continue. These
  ; values are never readiness proof and never drive a UI state: every app
  ; launch re-probes authoritative Windows state before resuming automatically.
  WriteRegStr HKCU "${MANUPRODUCTKEY}" "WindowsPrerequisiteReceiptSchema" "ai-security-scanner.windows-prerequisite-receipt/v1"
  WriteRegStr HKCU "${MANUPRODUCTKEY}" "WindowsPrerequisiteReceiptInstallerVersion" "${VERSION}"
  WriteRegStr HKCU "${MANUPRODUCTKEY}" "WindowsPrerequisiteReceiptResult" "checking"
  WriteRegDWORD HKCU "${MANUPRODUCTKEY}" "WindowsPrerequisiteResumeHint" 1
  DetailPrint "$(windowsPrerequisiteChecking)"

  ${IfNot} ${FileExists} "$INSTDIR\ai-security-scanner-cli.exe"
    Goto windows_prerequisite_retry
  ${EndIf}

  ; The backend owns a five-minute servicing deadline. This six-minute outer
  ; bound also covers startup and result serialization without making NSIS wait
  ; forever. No scanner output, target, credential, or user path is accepted.
  nsExec::ExecToStack /TIMEOUT=360000 '"$INSTDIR\ai-security-scanner-cli.exe" --json windows-installer-prerequisite'
  Pop $R0
  Pop $R1
  ${If} $R0 == "error"
    Goto windows_prerequisite_retry
  ${EndIf}
  ${If} $R0 == "timeout"
    Goto windows_prerequisite_retry
  ${EndIf}

  ; Accept only one of five complete, exact envelopes paired with its process
  ; exit class. The envelope intentionally contains no diagnostic or machine
  ; data and is never executed or copied into another command.
  ${If} $R0 = 0
    ${If} $R1 != '{"schema_version":"ai-security-scanner.windows-installer-prerequisite/v1","result_class":"ready","exit_code":0,"restart_required":false,"terminal":"complete"}'
    ${AndIf} $R1 != '{"schema_version":"ai-security-scanner.windows-installer-prerequisite/v1","result_class":"serviced","exit_code":0,"restart_required":false,"terminal":"complete"}'
      Goto windows_prerequisite_retry
    ${EndIf}
    WriteRegStr HKCU "${MANUPRODUCTKEY}" "WindowsPrerequisiteReceiptResult" "ready"
    WriteRegDWORD HKCU "${MANUPRODUCTKEY}" "WindowsPrerequisiteResumeHint" 0
    DetailPrint "$(windowsPrerequisiteReady)"
    Return
  ${ElseIf} $R0 = 10
    ${If} $R1 != '{"schema_version":"ai-security-scanner.windows-installer-prerequisite/v1","result_class":"restart_required","exit_code":10,"restart_required":true,"terminal":"complete"}'
      Goto windows_prerequisite_retry
    ${EndIf}
    WriteRegStr HKCU "${MANUPRODUCTKEY}" "WindowsPrerequisiteReceiptResult" "restart_required"
    WriteRegDWORD HKCU "${MANUPRODUCTKEY}" "WindowsPrerequisiteResumeHint" 1
    ; Tell interactive, passive, and silent NSIS hosts that Windows requested a
    ; restart without treating the installed app as failed or rolling it back.
    SetRebootFlag true
    SetErrorLevel 3010
    DetailPrint "$(windowsPrerequisiteRestart)"
    Return
  ${ElseIf} $R0 = 20
    ${If} $R1 != '{"schema_version":"ai-security-scanner.windows-installer-prerequisite/v1","result_class":"cancelled","exit_code":20,"restart_required":false,"terminal":"complete"}'
      Goto windows_prerequisite_retry
    ${EndIf}
  ${ElseIf} $R0 = 30
    ${If} $R1 != '{"schema_version":"ai-security-scanner.windows-installer-prerequisite/v1","result_class":"failed","exit_code":30,"restart_required":false,"terminal":"complete"}'
      Goto windows_prerequisite_retry
    ${EndIf}
  ${Else}
    Goto windows_prerequisite_retry
  ${EndIf}

  windows_prerequisite_retry:
  ; Cancellation, failure, timeout, a malformed helper result, and a missing
  ; helper all degrade only runtime-dependent tasks. Keep the installed shell,
  ; projects, reports, and unsigned exports available. The app rechecks the
  ; authoritative Windows state and retries the same fixed path automatically.
  WriteRegStr HKCU "${MANUPRODUCTKEY}" "WindowsPrerequisiteReceiptResult" "retry"
  WriteRegDWORD HKCU "${MANUPRODUCTKEY}" "WindowsPrerequisiteResumeHint" 1
  DetailPrint "$(windowsPrerequisiteRetry)"
FunctionEnd

Function .onInit
  ${GetOptions} $CMDLINE "/P" $PassiveMode
  ${IfNot} ${Errors}
    StrCpy $PassiveMode 1
  ${EndIf}

  ${GetOptions} $CMDLINE "/NS" $NoShortcutMode
  ${IfNot} ${Errors}
    StrCpy $NoShortcutMode 1
  ${EndIf}

  ${GetOptions} $CMDLINE "/UPDATE" $UpdateMode
  ${IfNot} ${Errors}
    StrCpy $UpdateMode 1
  ${EndIf}

  !if "${DISPLAYLANGUAGESELECTOR}" == "true"
    !insertmacro MUI_LANGDLL_DISPLAY
  !endif

  !insertmacro SetContext

  ${If} $INSTDIR == "${PLACEHOLDER_INSTALL_DIR}"
    ; Set default install location
    !if "${INSTALLMODE}" == "perMachine"
      ${If} ${RunningX64}
        !if "${ARCH}" == "x64"
          StrCpy $INSTDIR "$PROGRAMFILES64\${PRODUCTNAME}"
        !else if "${ARCH}" == "arm64"
          StrCpy $INSTDIR "$PROGRAMFILES64\${PRODUCTNAME}"
        !else
          StrCpy $INSTDIR "$PROGRAMFILES\${PRODUCTNAME}"
        !endif
      ${Else}
        StrCpy $INSTDIR "$PROGRAMFILES\${PRODUCTNAME}"
      ${EndIf}
    !else if "${INSTALLMODE}" == "currentUser"
      StrCpy $INSTDIR "$LOCALAPPDATA\${PRODUCTNAME}"
    !endif

    Call RestorePreviousInstallLocation
  ${EndIf}

  ; These calls are intentionally unconditional and precede every silent,
  ; passive, custom-page, and install-section path. Product-owned binaries and
  ; registration can therefore be repaired without making private data or a
  ; managed runtime an installer prerequisite.
  Call DetectVersionNeutralProductRepair


  !if "${INSTALLMODE}" == "both"
    !insertmacro MULTIUSER_INIT
  !endif

  ; Abort downgrades if they are disabled, in the modes that skip the reinstall page choice:
  ; silent, passive and update
  !if "${ALLOWDOWNGRADES}" == "false"
  ${If} ${Silent}
  ${OrIf} $PassiveMode = 1
  ${OrIf} $UpdateMode = 1
    ; Compare with the same installation the reinstall page would: a WiX one first
    Call FindWixInstall
    ${If} $R6 != ""
      ReadRegStr $R0 HKLM "$R6" "DisplayVersion"
    ${Else}
      ReadRegStr $R0 SHCTX "${UNINSTKEY}" "DisplayVersion"
    ${EndIf}
    nsis_tauri_utils::SemverCompare "${VERSION}" $R0
    Pop $R0
    ; If downgrading
    ${If} $R0 = -1
      ${If} ${Silent}
        System::Call 'kernel32::AttachConsole(i -1)i.r0'
        ${If} $0 <> 0
          System::Call 'kernel32::GetStdHandle(i -11)i.r0'
          System::call 'kernel32::SetConsoleTextAttribute(i r0, i 0x0004)' ; set red color
          FileWrite $0 "$(silentDowngrades)"
        ${EndIf}
      ${Else}
        MessageBox MB_ICONSTOP "$(silentDowngrades)"
      ${EndIf}
      Abort
    ${EndIf}
  ${EndIf}
  !endif
FunctionEnd

Section WebView2
  ; Check if Webview2 is already installed and skip this section
  ${If} ${RunningX64}
    ReadRegStr $4 HKLM "SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\${WEBVIEW2APPGUID}" "pv"
  ${Else}
    ReadRegStr $4 HKLM "SOFTWARE\Microsoft\EdgeUpdate\Clients\${WEBVIEW2APPGUID}" "pv"
  ${EndIf}
  ${If} $4 == ""
    ReadRegStr $4 HKCU "SOFTWARE\Microsoft\EdgeUpdate\Clients\${WEBVIEW2APPGUID}" "pv"
  ${EndIf}

  ${If} $4 == ""
    ; Webview2 installation
    ;
    ; Skip if updating
    ${If} $UpdateMode <> 1
      !if "${INSTALLWEBVIEW2MODE}" == "downloadBootstrapper"
        Delete "$TEMP\MicrosoftEdgeWebview2Setup.exe"
        DetailPrint "$(webview2Downloading)"
        NSISdl::download "https://go.microsoft.com/fwlink/p/?LinkId=2124703" "$TEMP\MicrosoftEdgeWebview2Setup.exe"
        Pop $0
        ${If} $0 == "success"
          DetailPrint "$(webview2DownloadSuccess)"
        ${Else}
          DetailPrint "$(webview2DownloadError)"
          Abort "$(webview2AbortError)"
        ${EndIf}
        StrCpy $6 "$TEMP\MicrosoftEdgeWebview2Setup.exe"
        Goto install_webview2
      !endif

      !if "${INSTALLWEBVIEW2MODE}" == "embedBootstrapper"
        Delete "$TEMP\MicrosoftEdgeWebview2Setup.exe"
        File "/oname=$TEMP\MicrosoftEdgeWebview2Setup.exe" "${WEBVIEW2BOOTSTRAPPERPATH}"
        DetailPrint "$(installingWebview2)"
        StrCpy $6 "$TEMP\MicrosoftEdgeWebview2Setup.exe"
        Goto install_webview2
      !endif

      !if "${INSTALLWEBVIEW2MODE}" == "offlineInstaller"
        Delete "$TEMP\MicrosoftEdgeWebView2RuntimeInstaller.exe"
        File "/oname=$TEMP\MicrosoftEdgeWebView2RuntimeInstaller.exe" "${WEBVIEW2INSTALLERPATH}"
        DetailPrint "$(installingWebview2)"
        StrCpy $6 "$TEMP\MicrosoftEdgeWebView2RuntimeInstaller.exe"
        Goto install_webview2
      !endif

      Goto webview2_done

      install_webview2:
        DetailPrint "$(installingWebview2)"
        ; $6 holds the path to the webview2 installer
        ExecWait "$6 ${WEBVIEW2INSTALLERARGS} /install" $1
        ${If} $1 = 0
          DetailPrint "$(webview2InstallSuccess)"
        ${Else}
          DetailPrint "$(webview2InstallError)"
          Abort "$(webview2AbortError)"
        ${EndIf}
      webview2_done:
    ${EndIf}
  ${Else}
    !if "${MINIMUMWEBVIEW2VERSION}" != ""
      ${VersionCompare} "${MINIMUMWEBVIEW2VERSION}" "$4" $R0
      ${If} $R0 = 1
        update_webview:
          DetailPrint "$(installingWebview2)"
          ${If} ${RunningX64}
            ReadRegStr $R1 HKLM "SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate" "path"
          ${Else}
            ReadRegStr $R1 HKLM "SOFTWARE\Microsoft\EdgeUpdate" "path"
          ${EndIf}
          ${If} $R1 == ""
            ReadRegStr $R1 HKCU "SOFTWARE\Microsoft\EdgeUpdate" "path"
          ${EndIf}
          ${If} $R1 != ""
            ; Chromium updater docs: https://source.chromium.org/chromium/chromium/src/+/main:docs/updater/user_manual.md
            ; Modified from "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft EdgeWebView\ModifyPath"
            ExecWait `"$R1" /install appguid=${WEBVIEW2APPGUID}&needsadmin=true` $1
            ${If} $1 = 0
              DetailPrint "$(webview2InstallSuccess)"
            ${Else}
              MessageBox MB_ICONEXCLAMATION|MB_ABORTRETRYIGNORE "$(webview2InstallError)" IDIGNORE ignore IDRETRY update_webview
              Quit
              ignore:
            ${EndIf}
          ${EndIf}
      ${EndIf}
    !endif
  ${EndIf}
SectionEnd

Section Install
  SetOutPath $INSTDIR

  !ifmacrodef NSIS_HOOK_PREINSTALL
    !insertmacro NSIS_HOOK_PREINSTALL
  !endif

  !insertmacro CheckIfAppIsRunning "$INSTDIR\${MAINBINARYNAME}.exe" "${PRODUCTNAME}"

  ; Copy main executable
  File "${MAINBINARYSRCPATH}"

  ; Copy resources
  {{#each resources_dirs}}
    CreateDirectory "$INSTDIR\\{{this}}"
  {{/each}}
  {{#each resources}}
    File /a "/oname={{this.[1]}}" "{{no-escape @key}}"
  {{/each}}

  ; Copy external binaries
  {{#each binaries}}
    File /a "/oname={{this}}" "{{no-escape @key}}"
  {{/each}}

  ; Create file associations
  {{#each file_associations as |association| ~}}
    {{#each association.ext as |ext| ~}}
       !insertmacro APP_ASSOCIATE "{{ext}}" "{{or association.name ext}}" "{{association-description association.description ext}}" "$\"$INSTDIR\${MAINBINARYNAME}.exe$\",0" "Open with ${PRODUCTNAME}" "$\"$INSTDIR\${MAINBINARYNAME}.exe$\" $\"%1$\""
    {{/each}}
  {{/each}}

  ; Register deep links
  {{#each deep_link_protocols as |protocol| ~}}
    WriteRegStr SHCTX "Software\Classes\\{{protocol}}" "URL Protocol" ""
    WriteRegStr SHCTX "Software\Classes\\{{protocol}}" "" "URL:${BUNDLEID} protocol"
    WriteRegStr SHCTX "Software\Classes\\{{protocol}}\DefaultIcon" "" "$\"$INSTDIR\${MAINBINARYNAME}.exe$\",0"
    WriteRegStr SHCTX "Software\Classes\\{{protocol}}\shell\open\command" "" "$\"$INSTDIR\${MAINBINARYNAME}.exe$\" $\"%1$\""
  {{/each}}

  ; Create uninstaller
  WriteUninstaller "$INSTDIR\uninstall.exe"

  ; Save $INSTDIR in registry for future installations
  WriteRegStr SHCTX "${MANUPRODUCTKEY}" "" $INSTDIR

  !if "${INSTALLMODE}" == "both"
    ; Save install mode to be selected by default for the next installation such as updating
    ; or when uninstalling
    WriteRegStr SHCTX "${UNINSTKEY}" $MultiUser.InstallMode 1
  !endif

  ; Remove old main binary if it doesn't match new main binary name
  ReadRegStr $OldMainBinaryName SHCTX "${UNINSTKEY}" "MainBinaryName"
  ${If} $OldMainBinaryName != ""
  ${AndIf} $OldMainBinaryName != "${MAINBINARYNAME}.exe"
    Delete "$INSTDIR\$OldMainBinaryName"
  ${EndIf}

  ; Save current MAINBINARYNAME for future updates
  WriteRegStr SHCTX "${UNINSTKEY}" "MainBinaryName" "${MAINBINARYNAME}.exe"

  ; Registry information for add/remove programs
  WriteRegStr SHCTX "${UNINSTKEY}" "DisplayName" "${PRODUCTNAME}"
  WriteRegStr SHCTX "${UNINSTKEY}" "DisplayIcon" "$\"$INSTDIR\${MAINBINARYNAME}.exe$\""
  WriteRegStr SHCTX "${UNINSTKEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr SHCTX "${UNINSTKEY}" "Publisher" "${MANUFACTURER}"
  WriteRegStr SHCTX "${UNINSTKEY}" "InstallLocation" "$\"$INSTDIR$\""
  WriteRegStr SHCTX "${UNINSTKEY}" "UninstallString" "$\"$INSTDIR\uninstall.exe$\""
  WriteRegDWORD SHCTX "${UNINSTKEY}" "NoModify" "1"
  WriteRegDWORD SHCTX "${UNINSTKEY}" "NoRepair" "1"

  ${GetSize} "$INSTDIR" "/M=uninstall.exe /S=0K /G=0" $0 $1 $2
  IntOp $0 $0 + ${ESTIMATEDSIZE}
  IntFmt $0 "0x%08X" $0
  WriteRegDWORD SHCTX "${UNINSTKEY}" "EstimatedSize" "$0"

  !if "${HOMEPAGE}" != ""
    WriteRegStr SHCTX "${UNINSTKEY}" "URLInfoAbout" "${HOMEPAGE}"
    WriteRegStr SHCTX "${UNINSTKEY}" "URLUpdateInfo" "${HOMEPAGE}"
    WriteRegStr SHCTX "${UNINSTKEY}" "HelpLink" "${HOMEPAGE}"
  !endif

  ; Create start menu shortcut
  !insertmacro MUI_STARTMENU_WRITE_BEGIN Application
    Call CreateOrUpdateStartMenuShortcut
  !insertmacro MUI_STARTMENU_WRITE_END

  ; Create desktop shortcut for silent and passive installers
  ; because finish page will be skipped
  ${If} $PassiveMode = 1
  ${OrIf} ${Silent}
    Call CreateOrUpdateDesktopShortcut
  ${EndIf}

  !ifmacrodef NSIS_HOOK_POSTINSTALL
    !insertmacro NSIS_HOOK_POSTINSTALL
  !endif

  ; Seed a verified private recovery copy before first launch. This bounded,
  ; non-executing optimization is deliberately non-fatal: app installation and
  ; independent work remain available even when the cache cannot be prepared.
  ; Registration overlays (stale/same-version/upgrade) preserve private runtime
  ; bytes exactly and leave any new-version preparation to the reopened app.
  ${If} $RegistrationOverlayMode = 0
    Call SeedManagedRuntimePrivateCache
  ${EndIf}

  ; Prepare Windows support only after every application binary and its
  ; registration have been installed. Failure can therefore never roll back or
  ; hide the application shell, and no later manual setup page is required.
  Call RunWindowsInstallerPrerequisiteCoordinator

  ; Auto close this page for passive mode
  ${If} $PassiveMode = 1
    SetAutoClose true
  ${EndIf}
SectionEnd

Function .onInstSuccess
  ; Check for `/R` flag only in silent and passive installers because
  ; GUI installer has a toggle for the user to (re)start the app
  ${If} $PassiveMode = 1
  ${OrIf} ${Silent}
    ${GetOptions} $CMDLINE "/R" $R0
    ${IfNot} ${Errors}
      ${GetOptions} $CMDLINE "/ARGS" $R0
      nsis_tauri_utils::RunAsUser "$INSTDIR\${MAINBINARYNAME}.exe" "$R0"
    ${EndIf}
  ${EndIf}
FunctionEnd

Function un.onInit
  !insertmacro SetContext

  !if "${INSTALLMODE}" == "both"
    !insertmacro MULTIUSER_UNINIT
  !endif

  !insertmacro MUI_UNGETLANGUAGE

  ${GetOptions} $CMDLINE "/P" $PassiveMode
  ${IfNot} ${Errors}
    StrCpy $PassiveMode 1
  ${EndIf}

  ${GetOptions} $CMDLINE "/UPDATE" $UpdateMode
  ${IfNot} ${Errors}
    StrCpy $UpdateMode 1
  ${EndIf}

  ; This default is intentionally immune to silent/passive command-line input.
  ; /UPDATE also forces app-only again inside the coordinator function.
  StrCpy $UninstallChoice "app-only"
FunctionEnd

Function un.RunProductUninstallCoordinator
  ; A future caller cannot turn an updater replacement into data cleanup by
  ; changing UI state. The CLI accepts no path override for this command.
  ${If} $UpdateMode = 1
    StrCpy $UninstallChoice "app-only"
  ${EndIf}

  un_coordinator_retry:
  StrCpy $UninstallCoordinatorOutput ""
  ${If} $UninstallChoice == "scan-tools"
    nsExec::ExecToStack /TIMEOUT=600000 '"$INSTDIR\ai-security-scanner-cli.exe" --json product-uninstall --mode scan-tools --non-interactive --coordinator-envelope'
  ${ElseIf} $UninstallChoice == "all-data"
    nsExec::ExecToStack /TIMEOUT=600000 '"$INSTDIR\ai-security-scanner-cli.exe" --json product-uninstall --mode all-data --non-interactive --confirmation "REMOVE ALL AI-SECURITY-SCANNER DATA" --coordinator-envelope'
  ${Else}
    nsExec::ExecToStack /TIMEOUT=600000 '"$INSTDIR\ai-security-scanner-cli.exe" --json product-uninstall --mode app-only --non-interactive --coordinator-envelope'
  ${EndIf}
  Pop $0
  Pop $UninstallCoordinatorOutput

  ${If} $UninstallCoordinatorOutput != ""
    DetailPrint "$(unCoordinatorRecordLabel) $UninstallCoordinatorOutput"
  ${EndIf}

  ${If} $0 == "error"
    DetailPrint "$(unCoordinatorStartFailed)"
    ${If} $PassiveMode <> 1
    ${AndIf} $UpdateMode <> 1
    ${AndIfNot} ${Silent}
      MessageBox MB_ICONSTOP "$(unCoordinatorStartFailed)"
    ${EndIf}
    StrCpy $UninstallCoordinatorResult "fatal"
    Return
  ${EndIf}

  ${If} $0 == "timeout"
    Call un.PersistCoordinatorReceipt
    DetailPrint "$(unCoordinatorTimedOut)"
    ${If} $PassiveMode <> 1
    ${AndIf} $UpdateMode <> 1
    ${AndIfNot} ${Silent}
      ${If} $UninstallReceiptPath == ""
        MessageBox MB_ICONSTOP "$(unCoordinatorTimedOut)"
      ${Else}
        MessageBox MB_ICONSTOP "$(unCoordinatorTimedOut)$\r$\n$\r$\n$(unCoordinatorReceiptSaved)$\r$\n$UninstallReceiptPath"
      ${EndIf}
    ${EndIf}
    StrCpy $UninstallCoordinatorResult "fatal"
    Return
  ${EndIf}

  ; The helper emits no progress output and exactly one fixed envelope at exit,
  ; so nsExec's idle timeout is also the operation's outer bound. Accept an exit
  ; code only when schema, selected mode, result class, embedded exit code, and
  ; terminal sentinel are all present in that complete bounded envelope.
  ${UnStrLoc} $1 $UninstallCoordinatorOutput '"schema_version":"ai-security-scanner.product-uninstall/v1"' ">"
  ${If} $1 != 1
    Goto un_coordinator_invalid_record
  ${EndIf}
  ${If} $UninstallChoice == "scan-tools"
    StrCpy $2 '"mode":"scan_tools"'
  ${ElseIf} $UninstallChoice == "all-data"
    StrCpy $2 '"mode":"all_data"'
  ${Else}
    StrCpy $2 '"mode":"app_only"'
  ${EndIf}
  ${UnStrLoc} $1 $UninstallCoordinatorOutput $2 ">"
  ${If} $1 == ""
    Goto un_coordinator_invalid_record
  ${EndIf}
  ${UnStrLoc} $1 $UninstallCoordinatorOutput '"terminal":"complete"}' ">"
  ${If} $1 == ""
    Goto un_coordinator_invalid_record
  ${EndIf}
  ${If} $0 = 0
    StrCpy $2 '"result_class":"completed","exit_code":0'
  ${ElseIf} $0 = 10
    StrCpy $2 '"result_class":"completed_with_retained_state","exit_code":10'
  ${ElseIf} $0 = 20
    StrCpy $2 '"result_class":"contact_not_stopped","exit_code":20'
  ${Else}
    Goto un_coordinator_invalid_record
  ${EndIf}
  ${UnStrLoc} $1 $UninstallCoordinatorOutput $2 ">"
  ${If} $1 == ""
    Goto un_coordinator_invalid_record
  ${EndIf}
  Goto un_coordinator_record_valid

  un_coordinator_invalid_record:
  Call un.PersistCoordinatorReceipt
  DetailPrint "$(unCoordinatorInvalidRecord)"
  ${If} $PassiveMode <> 1
  ${AndIf} $UpdateMode <> 1
  ${AndIfNot} ${Silent}
    MessageBox MB_ICONSTOP "$(unCoordinatorInvalidRecord)"
  ${EndIf}
  StrCpy $UninstallCoordinatorResult "fatal"
  Return

  un_coordinator_record_valid:
  ${If} $0 = 0
    StrCpy $UninstallCoordinatorResult "completed"
    Return
  ${EndIf}

  ${If} $0 = 10
    ; The coordinator has already stopped target contact and recorded exact,
    ; redacted retained-state classes. Ambiguous or failed cleanup is a warning,
    ; not a reason to delete by a broader heuristic or keep the application installed.
    Call un.PersistCoordinatorReceipt
    DetailPrint "$(unCoordinatorRetained)"
    ${If} $PassiveMode <> 1
    ${AndIf} $UpdateMode <> 1
    ${AndIfNot} ${Silent}
      ${If} $UninstallReceiptPath == ""
        MessageBox MB_ICONEXCLAMATION "$(unCoordinatorRetained)$\r$\n$\r$\n$(unCoordinatorReceiptFailed)"
      ${Else}
        MessageBox MB_ICONEXCLAMATION "$(unCoordinatorRetained)$\r$\n$\r$\n$(unCoordinatorReceiptSaved)$\r$\n$UninstallReceiptPath"
      ${EndIf}
    ${EndIf}
    StrCpy $UninstallCoordinatorResult "retained-warning"
    Return
  ${EndIf}

  ${If} $0 = 20
    ; Exit 20 alone means verified target contact did not stop. Interactive
    ; users can retry the same bounded coordinator operation without widening
    ; its scope. Headless callers receive exit 20 and retain all app binaries.
    ${If} $PassiveMode <> 1
    ${AndIf} $UpdateMode <> 1
    ${AndIfNot} ${Silent}
      MessageBox MB_ICONEXCLAMATION|MB_RETRYCANCEL "$(unCoordinatorContactNotStopped)" IDRETRY un_coordinator_retry
    ${EndIf}
    Call un.PersistCoordinatorReceipt
    DetailPrint "$(unCoordinatorContactRetained)"
    StrCpy $UninstallCoordinatorResult "contact-not-stopped"
    Return
  ${EndIf}

  ; Any other code is a coordinator invocation/contract failure before NSIS
  ; has permission to remove its controller. Never reinterpret it as a cleanup
  ; warning and never continue silently.
  Call un.PersistCoordinatorReceipt
  DetailPrint "$(unCoordinatorFatal)"
  ${If} $PassiveMode <> 1
  ${AndIf} $UpdateMode <> 1
  ${AndIfNot} ${Silent}
    ${If} $UninstallReceiptPath == ""
      MessageBox MB_ICONSTOP "$(unCoordinatorFatal)"
    ${Else}
      MessageBox MB_ICONSTOP "$(unCoordinatorFatal)$\r$\n$\r$\n$(unCoordinatorReceiptSaved)$\r$\n$UninstallReceiptPath"
    ${EndIf}
  ${EndIf}
  StrCpy $UninstallCoordinatorResult "fatal"
FunctionEnd

Function un.PersistCoordinatorReceipt
  ${If} $UninstallReceiptPath != ""
    Return
  ${EndIf}
  ${If} $UninstallCoordinatorOutput == ""
    Return
  ${EndIf}

  ; GetTempFileName atomically creates one installer-owned, unpredictable file
  ; beneath Windows' temp directory. The CLI never receives this path, and no
  ; caller can redirect the coordinator to an arbitrary location.
  ClearErrors
  GetTempFileName $UninstallReceiptPath $TEMP
  ${If} ${Errors}
    StrCpy $UninstallReceiptPath ""
    DetailPrint "$(unCoordinatorReceiptFailed)"
    Return
  ${EndIf}
  ClearErrors
  FileOpen $1 "$UninstallReceiptPath" w
  ${If} ${Errors}
    Delete "$UninstallReceiptPath"
    StrCpy $UninstallReceiptPath ""
    DetailPrint "$(unCoordinatorReceiptFailed)"
    Return
  ${EndIf}
  FileWrite $1 "$UninstallCoordinatorOutput$\r$\n"
  FileClose $1
  ${If} ${Errors}
    Delete "$UninstallReceiptPath"
    StrCpy $UninstallReceiptPath ""
    DetailPrint "$(unCoordinatorReceiptFailed)"
    Return
  ${EndIf}
  DetailPrint "$(unCoordinatorReceiptSaved) $UninstallReceiptPath"
FunctionEnd

Function un.AppendPostconditionReceipt
  Call un.PersistCoordinatorReceipt
  ${If} $UninstallReceiptPath == ""
    Return
  ${EndIf}
  ClearErrors
  FileOpen $1 "$UninstallReceiptPath" a
  ${If} ${Errors}
    DetailPrint "$(unCoordinatorReceiptFailed)"
    Return
  ${EndIf}
  FileWrite $1 '{"schema_version":"ai-security-scanner.nsis-uninstall/v1","result":"partial","reason_code":"known_app_or_registration_retained"}$\r$\n'
  FileClose $1
  ${If} ${Errors}
    DetailPrint "$(unCoordinatorReceiptFailed)"
  ${EndIf}
FunctionEnd

Section Uninstall

  !ifmacrodef NSIS_HOOK_PREUNINSTALL
    !insertmacro NSIS_HOOK_PREUNINSTALL
  !endif

  !insertmacro CheckIfAppIsRunning "$INSTDIR\${MAINBINARYNAME}.exe" "${PRODUCTNAME}"

  ; BEGIN AI SECURITY SCANNER BOUNDED UNINSTALL DISPATCH
  ; The fixed bundled CLI stops dispatch/verified target contact and performs
  ; only the exact selected product cleanup. It runs after app-close handling
  ; and before NSIS deletes the CLI or any other application binary.
  Call un.RunProductUninstallCoordinator
  ${If} $UninstallCoordinatorResult == "contact-not-stopped"
    SetErrorLevel 20
    Quit
  ${ElseIf} $UninstallCoordinatorResult == "fatal"
    SetErrorLevel 1
    Quit
  ${EndIf}

  StrCpy $UninstallPartialOutcome 0
  ${If} $UninstallCoordinatorResult == "retained-warning"
  ${AndIf} $UpdateMode <> 1
    StrCpy $UninstallPartialOutcome 1
  ${EndIf}

  ; Snapshot the two exact current-user product values before NSIS removes app
  ; files. /UPDATE must preserve both. App-only and scan-tools remove only the
  ; default install-path value while preserving the selected installer language.
  StrCpy $UninstallInstallPathRegistrationPresent 0
  ClearErrors
  ReadRegStr $UninstallInstallPathRegistration HKCU "${MANUPRODUCTKEY}" ""
  ${IfNot} ${Errors}
    StrCpy $UninstallInstallPathRegistrationPresent 1
  ${EndIf}
  StrCpy $UninstallInstallerLanguagePresent 0
  ClearErrors
  ReadRegStr $UninstallInstallerLanguage HKCU "${MANUPRODUCTKEY}" "Installer Language"
  ${IfNot} ${Errors}
    StrCpy $UninstallInstallerLanguagePresent 1
  ${EndIf}
  ; END AI SECURITY SCANNER BOUNDED UNINSTALL DISPATCH

  ; Delete the app directory and its content from disk
  ; Copy main executable
  Delete "$INSTDIR\${MAINBINARYNAME}.exe"

  ; Delete resources
  {{#each resources}}
    Delete "$INSTDIR\\{{this.[1]}}"
  {{/each}}

  ; Delete external binaries
  {{#each binaries}}
    Delete "$INSTDIR\\{{this}}"
  {{/each}}

  ; Delete app associations
  {{#each file_associations as |association| ~}}
    {{#each association.ext as |ext| ~}}
      !insertmacro APP_UNASSOCIATE "{{ext}}" "{{or association.name ext}}"
    {{/each}}
  {{/each}}

  ; Delete deep links
  {{#each deep_link_protocols as |protocol| ~}}
    ReadRegStr $R7 SHCTX "Software\Classes\\{{protocol}}\shell\open\command" ""
    ${If} $R7 == "$\"$INSTDIR\${MAINBINARYNAME}.exe$\" $\"%1$\""
      DeleteRegKey SHCTX "Software\Classes\\{{protocol}}"
    ${EndIf}
  {{/each}}


  ; Delete uninstaller
  Delete "$INSTDIR\uninstall.exe"

  {{#each resources_ancestors}}
  RMDir /REBOOTOK "$INSTDIR\\{{this}}"
  {{/each}}
  RMDir "$INSTDIR"

  ; Remove shortcuts if not updating
  ${If} $UpdateMode <> 1
    !insertmacro DeleteAppUserModelId

    ; Remove start menu shortcut
    !insertmacro MUI_STARTMENU_GETFOLDER Application $AppStartMenuFolder
    !insertmacro IsShortcutTarget "$SMPROGRAMS\$AppStartMenuFolder\${PRODUCTNAME}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe"
    Pop $0
    ${If} $0 = 1
      !insertmacro UnpinShortcut "$SMPROGRAMS\$AppStartMenuFolder\${PRODUCTNAME}.lnk"
      Delete "$SMPROGRAMS\$AppStartMenuFolder\${PRODUCTNAME}.lnk"
      RMDir "$SMPROGRAMS\$AppStartMenuFolder"
    ${EndIf}
    !insertmacro IsShortcutTarget "$SMPROGRAMS\${PRODUCTNAME}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe"
    Pop $0
    ${If} $0 = 1
      !insertmacro UnpinShortcut "$SMPROGRAMS\${PRODUCTNAME}.lnk"
      Delete "$SMPROGRAMS\${PRODUCTNAME}.lnk"
    ${EndIf}

    ; Remove desktop shortcuts
    !insertmacro IsShortcutTarget "$DESKTOP\${PRODUCTNAME}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe"
    Pop $0
    ${If} $0 = 1
      !insertmacro UnpinShortcut "$DESKTOP\${PRODUCTNAME}.lnk"
      Delete "$DESKTOP\${PRODUCTNAME}.lnk"
    ${EndIf}
  ${EndIf}

  ; Remove registry information for add/remove programs
  !if "${INSTALLMODE}" == "both"
    DeleteRegKey SHCTX "${UNINSTKEY}"
  !else if "${INSTALLMODE}" == "perMachine"
    DeleteRegKey HKLM "${UNINSTKEY}"
  !else
    DeleteRegKey HKCU "${UNINSTKEY}"
  !endif

  ; ai-security-scanner does not create a Windows Run entry. Do not delete a
  ; same-named value that another program or the user may own.

  ; BEGIN AI SECURITY SCANNER EXACT REGISTRATION AND POSTCONDITIONS
  ; Product data and disposable runtime cleanup is coordinator-owned. NSIS
  ; never recursively removes an application-data parent or guesses ownership
  ; from a name. /UPDATE preserves both product values. App-only and scan-tools
  ; remove the stale exact install-path registration but preserve the selected
  ; installer language. All-data removes only the exact product key, then the
  ; exact manufacturer key if it is empty.
  ${If} $UpdateMode <> 1
    ${If} $UninstallChoice == "all-data"
      DeleteRegKey HKCU "${MANUPRODUCTKEY}"
      DeleteRegKey /ifempty HKCU "${MANUKEY}"
    ${Else}
      DeleteRegValue HKCU "${MANUPRODUCTKEY}" ""
    ${EndIf}
  ${EndIf}

  ; Verify the two known app binaries and exact registration postconditions.
  ; A mismatch becomes an explicit partial result (exit 10); it never widens
  ; deletion to a parent directory or an ownership guess.
  StrCpy $UninstallPostconditionFailed 0
  ${If} ${FileExists} "$INSTDIR\${MAINBINARYNAME}.exe"
    StrCpy $UninstallPostconditionFailed 1
  ${EndIf}
  {{#each binaries}}
  ${If} ${FileExists} "$INSTDIR\\{{this}}"
    StrCpy $UninstallPostconditionFailed 1
  ${EndIf}
  {{/each}}
  ${If} ${FileExists} "$INSTDIR\uninstall.exe"
    StrCpy $UninstallPostconditionFailed 1
  ${EndIf}
  ClearErrors
  ReadRegStr $0 HKCU "${UNINSTKEY}" ""
  ${IfNot} ${Errors}
    StrCpy $UninstallPostconditionFailed 1
  ${EndIf}
  ClearErrors
  ReadRegStr $0 HKCU "${UNINSTKEY}" "DisplayName"
  ${IfNot} ${Errors}
    StrCpy $UninstallPostconditionFailed 1
  ${EndIf}
  ClearErrors
  StrCpy $0 ""
  EnumRegValue $0 HKCU "${UNINSTKEY}" 0
  ${If} $0 != ""
    StrCpy $UninstallPostconditionFailed 1
  ${EndIf}
  ClearErrors
  StrCpy $0 ""
  EnumRegKey $0 HKCU "${UNINSTKEY}" 0
  ${If} $0 != ""
    StrCpy $UninstallPostconditionFailed 1
  ${EndIf}

  ${If} $UpdateMode = 1
    ${If} $UninstallInstallPathRegistrationPresent = 1
      ClearErrors
      ReadRegStr $0 HKCU "${MANUPRODUCTKEY}" ""
      ${If} ${Errors}
        StrCpy $UninstallPostconditionFailed 1
      ${ElseIf} $0 != $UninstallInstallPathRegistration
        StrCpy $UninstallPostconditionFailed 1
      ${EndIf}
    ${EndIf}
    ${If} $UninstallInstallerLanguagePresent = 1
      ClearErrors
      ReadRegStr $0 HKCU "${MANUPRODUCTKEY}" "Installer Language"
      ${If} ${Errors}
        StrCpy $UninstallPostconditionFailed 1
      ${ElseIf} $0 != $UninstallInstallerLanguage
        StrCpy $UninstallPostconditionFailed 1
      ${EndIf}
    ${EndIf}
  ${ElseIf} $UninstallChoice == "all-data"
    ClearErrors
    ReadRegStr $0 HKCU "${MANUPRODUCTKEY}" ""
    ${IfNot} ${Errors}
      StrCpy $UninstallPostconditionFailed 1
    ${EndIf}
    ClearErrors
    ReadRegStr $0 HKCU "${MANUPRODUCTKEY}" "Installer Language"
    ${IfNot} ${Errors}
      StrCpy $UninstallPostconditionFailed 1
    ${EndIf}
    ClearErrors
    StrCpy $0 ""
    EnumRegValue $0 HKCU "${MANUPRODUCTKEY}" 0
    ${If} $0 != ""
      StrCpy $UninstallPostconditionFailed 1
    ${EndIf}
    ClearErrors
    StrCpy $0 ""
    EnumRegKey $0 HKCU "${MANUPRODUCTKEY}" 0
    ${If} $0 != ""
      StrCpy $UninstallPostconditionFailed 1
    ${EndIf}
  ${Else}
    ClearErrors
    ReadRegStr $0 HKCU "${MANUPRODUCTKEY}" ""
    ${IfNot} ${Errors}
      StrCpy $UninstallPostconditionFailed 1
    ${EndIf}
    ${If} $UninstallInstallerLanguagePresent = 1
      ClearErrors
      ReadRegStr $0 HKCU "${MANUPRODUCTKEY}" "Installer Language"
      ${If} ${Errors}
        StrCpy $UninstallPostconditionFailed 1
      ${ElseIf} $0 != $UninstallInstallerLanguage
        StrCpy $UninstallPostconditionFailed 1
      ${EndIf}
    ${EndIf}
  ${EndIf}

  ${If} $UninstallPostconditionFailed = 1
    StrCpy $UninstallPartialOutcome 1
    Call un.AppendPostconditionReceipt
    DetailPrint "$(unPostconditionPartial)"
    ${If} $PassiveMode <> 1
    ${AndIf} $UpdateMode <> 1
    ${AndIfNot} ${Silent}
      ${If} $UninstallReceiptPath == ""
        MessageBox MB_ICONEXCLAMATION "$(unPostconditionPartial)"
      ${Else}
        MessageBox MB_ICONEXCLAMATION "$(unPostconditionPartial)$\r$\n$\r$\n$(unCoordinatorReceiptSaved)$\r$\n$UninstallReceiptPath"
      ${EndIf}
    ${EndIf}
  ${EndIf}
  ${If} $UninstallPartialOutcome = 1
    SetErrorLevel 10
  ${EndIf}
  ; END AI SECURITY SCANNER EXACT REGISTRATION AND POSTCONDITIONS

  !ifmacrodef NSIS_HOOK_POSTUNINSTALL
    !insertmacro NSIS_HOOK_POSTUNINSTALL
  !endif

  ; Auto close if passive mode or updating
  ${If} $PassiveMode = 1
  ${OrIf} $UpdateMode = 1
    SetAutoClose true
  ${EndIf}
SectionEnd

Function RestorePreviousInstallLocation
  ReadRegStr $4 SHCTX "${MANUPRODUCTKEY}" ""
  StrCmp $4 "" +2 0
    StrCpy $INSTDIR $4
FunctionEnd

Function DetectVersionNeutralProductRepair
  StrCpy $RegistrationOverlayMode 0
  ; Bind automatic repair to the exact HKCU product identity and its internally
  ; consistent install path. DisplayVersion is deliberately not an ownership
  ; proof: a stale registration from any product version can be repaired. This
  ; function performs no deletion or external command and never inspects or
  ; claims WSL/runtime state.
  !if "${INSTALLMODE}" == "currentUser"
    ReadRegStr $R2 HKCU "${UNINSTKEY}" "DisplayName"
    ReadRegStr $R3 HKCU "${UNINSTKEY}" "Publisher"
    ReadRegStr $R4 HKCU "${UNINSTKEY}" "DisplayVersion"
    ReadRegStr $R5 HKCU "${UNINSTKEY}" "InstallLocation"
    ReadRegStr $R6 HKCU "${UNINSTKEY}" "UninstallString"
    ReadRegStr $R7 HKCU "${UNINSTKEY}" "MainBinaryName"
    StrCpy $R8 '$\"$INSTDIR$\"'
    StrCpy $R9 '$\"$INSTDIR\uninstall.exe$\"'
    ${If} $R2 == "${PRODUCTNAME}"
    ${AndIf} $R3 == "${MANUFACTURER}"
    ${AndIf} $R5 == $R8
    ${AndIf} $R6 == $R9
    ${AndIf} $R7 == "${MAINBINARYNAME}.exe"
      ${If} ${FileExists} "$INSTDIR\${MAINBINARYNAME}.exe"
      ${AndIf} ${FileExists} "$INSTDIR\uninstall.exe"
        nsis_tauri_utils::SemverCompare "${VERSION}" $R4
        Pop $R1
        ; Retain the comparison result when this detector leaves a downgrade
        ; or malformed comparison on the ordinary installer path.
        StrCpy $R0 $R1
        ${If} $R1 = 0
          StrCpy $RegistrationOverlayMode 2
          DetailPrint "Repairing this ai-security-scanner version in place."
        ${ElseIf} $R1 = 1
          StrCpy $RegistrationOverlayMode 3
          DetailPrint "Upgrading ai-security-scanner in place while preserving its data."
        ${EndIf}
      ${Else}
        ; A missing product binary makes the old UninstallString unusable. Keep
        ; every remaining byte and let the normal Install section replace only
        ; this candidate's files and registry values.
        StrCpy $RegistrationOverlayMode 1
        StrCpy $R0 0
        DetailPrint "Repairing an incomplete ai-security-scanner installation in place."
      ${EndIf}
    ${EndIf}
  !endif
FunctionEnd

Function Skip
  Abort
FunctionEnd

Function SkipDirectoryIfRepairOrPassive
  ${If} $RegistrationOverlayMode <> 0
  ${OrIf} $PassiveMode = 1
    Abort
  ${EndIf}
FunctionEnd

Function SkipIfPassive
  ${IfThen} $PassiveMode = 1  ${|} Abort ${|}
FunctionEnd
Function un.SkipIfPassive
  ${IfThen} $PassiveMode = 1  ${|} Abort ${|}
FunctionEnd

Function CreateOrUpdateStartMenuShortcut
  ; We used to use product name as MAINBINARYNAME
  ; migrate old shortcuts to target the new MAINBINARYNAME
  StrCpy $R0 0

  !insertmacro IsShortcutTarget "$SMPROGRAMS\$AppStartMenuFolder\${PRODUCTNAME}.lnk" "$INSTDIR\$OldMainBinaryName"
  Pop $0
  ${If} $0 = 1
    !insertmacro SetShortcutTarget "$SMPROGRAMS\$AppStartMenuFolder\${PRODUCTNAME}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe"
    StrCpy $R0 1
  ${EndIf}

  !insertmacro IsShortcutTarget "$SMPROGRAMS\${PRODUCTNAME}.lnk" "$INSTDIR\$OldMainBinaryName"
  Pop $0
  ${If} $0 = 1
    !insertmacro SetShortcutTarget "$SMPROGRAMS\${PRODUCTNAME}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe"
    StrCpy $R0 1
  ${EndIf}

  ${If} $R0 = 1
    Return
  ${EndIf}

  ; Skip creating shortcut if in update mode or no shortcut mode
  ; but always create if migrating from wix
  ${If} $WixMode = 0
    ${If} $UpdateMode = 1
    ${OrIf} $NoShortcutMode = 1
      Return
    ${EndIf}
  ${EndIf}

  !if "${STARTMENUFOLDER}" != ""
    CreateDirectory "$SMPROGRAMS\$AppStartMenuFolder"
    CreateShortcut "$SMPROGRAMS\$AppStartMenuFolder\${PRODUCTNAME}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe"
    !insertmacro SetLnkAppUserModelId "$SMPROGRAMS\$AppStartMenuFolder\${PRODUCTNAME}.lnk"
  !else
    CreateShortcut "$SMPROGRAMS\${PRODUCTNAME}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe"
    !insertmacro SetLnkAppUserModelId "$SMPROGRAMS\${PRODUCTNAME}.lnk"
  !endif
FunctionEnd

Function CreateOrUpdateDesktopShortcut
  ; We used to use product name as MAINBINARYNAME
  ; migrate old shortcuts to target the new MAINBINARYNAME
  !insertmacro IsShortcutTarget "$DESKTOP\${PRODUCTNAME}.lnk" "$INSTDIR\$OldMainBinaryName"
  Pop $0
  ${If} $0 = 1
    !insertmacro SetShortcutTarget "$DESKTOP\${PRODUCTNAME}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe"
    Return
  ${EndIf}

  ; Skip creating shortcut if in update mode or no shortcut mode
  ; but always create if migrating from wix
  ${If} $WixMode = 0
    ${If} $UpdateMode = 1
    ${OrIf} $NoShortcutMode = 1
      Return
    ${EndIf}
  ${EndIf}

  CreateShortcut "$DESKTOP\${PRODUCTNAME}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe"
  !insertmacro SetLnkAppUserModelId "$DESKTOP\${PRODUCTNAME}.lnk"
FunctionEnd
