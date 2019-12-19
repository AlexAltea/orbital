# Devices

## `/dev/aoutX`? (X is a number)

### IOCTLs

Partial list of IOCTL codes:

| Name                                                            | Code       |
|-----------------------------------------------------------------|------------|
| *SNDCTL_DSP_COOKEDMODE*                                         | 0x80045010 |
| *SNDCTL_DSP_SETFMT*                                             | 0x80045010 |
| *SNDCTL_DSP_SETTRIGGER*                                         | 0x80045010 |
| *SOUND_PCM_READ_BITS*                                           | 0x40045005 |
| *SOUND_PCM_READ_CHANNELS*                                       | 0x40045002 |
| *SOUND_PCM_READ_RATE*                                           | 0x40045002 |


## `/dev/av_control`

### IOCTLs

Partial list of IOCTL codes:

| Name                                                            | Code       |
|-----------------------------------------------------------------|------------|
| *SCE_SYS_AV_CONTROL_IOCTL_BLND_DMIF_CLEAR_UF_INT*               | 0xC0049A27 |
| *SCE_SYS_AV_CONTROL_IOCTL_BLND_ENABLE_PTI*                      | 0xC0089A1E |
| *SCE_SYS_AV_CONTROL_IOCTL_CRTC_BLANK*                           | 0xC0089A02 |
| *SCE_SYS_AV_CONTROL_IOCTL_CRTC_CANCEL_VGA*                      | 0x20009A0A |
| *SCE_SYS_AV_CONTROL_IOCTL_CRTC_CHECK_READY_FLAG*                | 0xC0089A29 |
| *SCE_SYS_AV_CONTROL_IOCTL_CRTC_ENABLE*                          | 0xC0089A01 |
| *SCE_SYS_AV_CONTROL_IOCTL_CRTC_ENABLE_DATA_REQ*                 | 0xC0089A03 |
| *SCE_SYS_AV_CONTROL_IOCTL_CRTC_ENABLE_DCFE_CLOCK*               | 0xC0089A06 |
| *SCE_SYS_AV_CONTROL_IOCTL_CRTC_ENABLE_PREFETCH*                 | 0xC0089A08 |
| *SCE_SYS_AV_CONTROL_IOCTL_CRTC_PRE_BLANK*                       | 0xC0089A28 |
| *SCE_SYS_AV_CONTROL_IOCTL_CRTC_SET_DBUFF*                       | 0xC0089A04 |
| *SCE_SYS_AV_CONTROL_IOCTL_CRTC_SET_HBLANK_EARLY*                | 0xC0089A09 |
| *SCE_SYS_AV_CONTROL_IOCTL_CRTC_SET_MASTER_UPDATE_LOCK*          | 0xC0089A05 |
| *SCE_SYS_AV_CONTROL_IOCTL_CRTC_SET_TIMING*                      | 0xC0189A07 |
| *SCE_SYS_AV_CONTROL_IOCTL_DP_ENABLE_TSINK*                      | 0xC0089A21 |
| *SCE_SYS_AV_CONTROL_IOCTL_DP_GET_DPRX_CRC*                      | 0xC0189A22 |
| *SCE_SYS_AV_CONTROL_IOCTL_DP_OFF*                               | 0xC0189A10 |
| *SCE_SYS_AV_CONTROL_IOCTL_DP_ON*                                | 0xC0189A0F |
| *SCE_SYS_AV_CONTROL_IOCTL_DP_SET_MSA*                           | 0xC0109A11 |
| *SCE_SYS_AV_CONTROL_IOCTL_FMT_DISABLE_TRUNC*                    | 0xC0049A1B |
| *SCE_SYS_AV_CONTROL_IOCTL_FMT_ENABLE_CRC*                       | 0xC00C9A17 |
| *SCE_SYS_AV_CONTROL_IOCTL_FMT_ENABLE_TRUNC*                     | 0xC0089A1A |
| *SCE_SYS_AV_CONTROL_IOCTL_FMT_GET_CRC*                          | 0xC0109A18 |
| *SCE_SYS_AV_CONTROL_IOCTL_FMT_SET_CLAMP*                        | 0xC0109A19 |
| *SCE_SYS_AV_CONTROL_IOCTL_FMT_SET_PIXENC*                       | 0xC0089A13 |
| *SCE_SYS_AV_CONTROL_IOCTL_FMT_SET_SPA_DITHER*                   | 0xC0109A16 |
| *SCE_SYS_AV_CONTROL_IOCTL_FMT_SET_SRC*                          | 0xC0089A1C |
| *SCE_SYS_AV_CONTROL_IOCTL_FMT_SET_SUB_MODE*                     | 0xC0089A14 |
| *SCE_SYS_AV_CONTROL_IOCTL_FMT_SET_TRUNC_DEPTH*                  | 0xC0089A15 |
| *SCE_SYS_AV_CONTROL_IOCTL_FMT_SET_TRUNC_MODE*                   | 0xC0089A1D |
| *SCE_SYS_AV_CONTROL_IOCTL_MPCT_SETUP*                           | 0x20009A12 |
| *SCE_SYS_AV_CONTROL_IOCTL_NOTIFY_HDMI_CONNECT_STATE*            | 0xC0049A24 |
| *SCE_SYS_AV_CONTROL_IOCTL_NOTIFY_SETMODE_SOC*                   | 0x20009A26 |
| *SCE_SYS_AV_CONTROL_IOCTL_PLL_SET_APLL*                         | 0xC0049A0C |
| *SCE_SYS_AV_CONTROL_IOCTL_PLL_SET_DISPCLK*                      | 0xC0109A0E |
| *SCE_SYS_AV_CONTROL_IOCTL_PLL_SET_PPLL*                         | 0xC0109A0D |
| *SCE_SYS_AV_CONTROL_IOCTL_UPDATE_HDMI_CONNECT_STATE_BY_SETMODE* | 0x20009A25 |
| *SCE_SYS_AV_CONTROL_IOCTL_UPDATE_VMODE_PARAMS*                  | 0xC0609A23 |


## `/dev/dbggcc`

### IOCTLs

Partial list of IOCTL codes:

| Name                                                            | Code       |
|-----------------------------------------------------------------|------------|
| *SCE_DBGGC_IOCTL_WRITE_REGISTERS*                               |   *???*    |


## `/dev/dce`

### IOCTLs

Partial list of IOCTL codes:

| Name                                                            | Code       |
|-----------------------------------------------------------------|------------|
| *SCE_SYS_DCE_IOCTL_FLIP_CONTROL*                                | 0xC0308203 |
| *SCE_SYS_DCE_IOCTL_SUBMIT_REQUEST*                              | 0xC0308204 |
| *SCE_SYS_DCE_IOCTL_REGISTER_BUFFER*                             | 0xC0308206 |
| *SCE_SYS_DCE_IOCTL_REGISTER_BUFFER_ATTRIBUTE*                   | 0xC0308207 |


## `/dev/dipsw`

### IOCTLs

Partial list of IOCTL codes:

| Name                                                            | Code       |
|-----------------------------------------------------------------|------------|
| *SCE_KERNEL_INITIALIZE_DIPSW*                                   | 0x20008800 |
| *SCE_KERNEL_SET_DIPSW*                                          | 0x80028801 |
| *SCE_KERNEL_UNSET_DIPSW*                                        | 0x80028802 |
| *SCE_KERNEL_CHECK_DIPSW*                                        | 0xC0308207 |
| *SCE_KERNEL_READ_DIPSW_DATA*                                    | 0x80108804 |
| *SCE_KERNEL_WRITE_DIPSW_DATA*                                   | 0xC0308207 |


## `/dev/gc`

### IOCTLs

| Name                                                            | Code       |
|-----------------------------------------------------------------|------------|
| *???*                                                           | 0xC0108102 |

#### 0xC0108102

Seems involved in submitting PM4 command lists to the CP.


## `/dev/hdmi`

### IOCTLs

Partial list of IOCTL codes:

| Name                                                            | Code       |
|-----------------------------------------------------------------|------------|
| *SCE_HDMI_IOCTL_AUDIO_ASP*                                      | 0xC0048D18 |
| *SCE_HDMI_IOCTL_AUDIO_CONFIG*                                   | 0xC01C8D03 |
| *SCE_HDMI_IOCTL_AUDIO_COPY_CONTROL*                             | 0xC01C8D06 |
| *SCE_HDMI_IOCTL_AUDIO_MUTE*                                     | 0xC0048D05 |
| *SCE_HDMI_IOCTL_CONTROL_AVOUT*                                  | 0xC0048D08 |
| *SCE_HDMI_IOCTL_CONTROL_HMDVIEW_MODE*                           | 0xC0048D11 |
| *SCE_HDMI_IOCTL_CSC_DIRECT*                                     | 0xC0068D09 |
| *SCE_HDMI_IOCTL_GET_AKSV*                                       | 0xC0088D0F |
| *SCE_HDMI_IOCTL_GET_DP_STATE*                                   | 0xC0108D1A |
| *SCE_HDMI_IOCTL_GET_HDMI_CONFIG*                                | 0xC0108D10 |
| *SCE_HDMI_IOCTL_GET_HDMI_STATE*                                 | 0xC0088D0C |
| *SCE_HDMI_IOCTL_IC_INIT*                                        | 0x20008D01 |
| *SCE_HDMI_IOCTL_ORBIS_AUDIO_UPDATE_TICK_PARAMS*                 | 0xC0045002 |
| *SCE_HDMI_IOCTL_SET_GAMUTMETA_DATA*                             | 0xC0108D07 |
| *SCE_HDMI_IOCTL_SNDCTL_DSP_CHANNELS*                            | 0xC0045002 |
| *SCE_HDMI_IOCTL_SNDCTL_DSP_SETFMT*                              | 0x40045004 |
| *SCE_HDMI_IOCTL_SNDCTL_DSP_SETFRAGMENT*                         | 0x40045004 |
| *SCE_HDMI_IOCTL_SNDCTL_DSP_SPEED*                               | 0xC0045002 |
| *SCE_HDMI_IOCTL_SNDCTL_DSP_SYNCGROUP*                           | 0xC048501C |
| *SCE_HDMI_IOCTL_VIDEO_CONFIG*                                   | 0xC0148D02 |


## `/dev/hmd_cmd`

### IOCTLs

Partial list of IOCTL codes:

| Name                                                            | Code       |
|-----------------------------------------------------------------|------------|
| *SCE_HMD_CMD_IOCTL_GET_MENU_SETTING*                            | 0x8008A018 |
| *SCE_HMD_CMD_IOCTL_SET_MENU_SETTING*                            | 0x8001A02D |


## `/dev/mbus_kmod`?

### IOCTLs

Partial list of IOCTL codes:

| Name                                                            | Code       |
|-----------------------------------------------------------------|------------|
| *SCE_MBUS_KMOD_IOCTL_GET_DEVICE_INFO*                           | 0xC0288C01 |
| *SCE_MBUS_KMOD_IOCTL_GET_DEVICE_PROPERTY*                       | 0xC1108C03 |
| *SCE_MBUS_KMOD_IOCTL_SET_SYSTEM_STATE*                          | 0xC0108C02 |
| *SCE_MBUS_KMOD_IOCTL_SET_USB_POWER_BLACK_LIST*                  | 0xC0188C04 |

## `/dev/devact/`

### IOCTLs

Partial list of IOCTL codes:

| Name                                                            | Code       |
|-----------------------------------------------------------------|------------|
| *???*                                                           | 0xC0045312h|


## `/dev/mixerX` (X is a number)

### IOCTLs

Partial list of IOCTL codes:

| Name                                                            | Code       |
|-----------------------------------------------------------------|------------|
| *SCE_PFS_IOCTL_SBRAM_INIT*                                      | 0x20009109 |


## PFS

### IOCTLs

Partial list of IOCTL codes:

| Name                                                            | Code       |
|-----------------------------------------------------------------|------------|
| *SOUND_MIXER_WRITE_MIC*                                         | 0xC0044D07 |


## `/dev/spdif`?

### IOCTLs

Partial list of IOCTL codes:

| Name                                                            | Code       |
|-----------------------------------------------------------------|------------|
| *SCE_SPDIF_IOCTL_SNDCTL_DSP_CHANNELS*                           | 0xC0045002 |
| *SCE_SPDIF_IOCTL_SNDCTL_DSP_SETFMT*                             | 0x40045004 |
| *SCE_SPDIF_IOCTL_SNDCTL_DSP_SETFRAGMENT*                        | 0x40045004 |
| *SCE_SPDIF_IOCTL_SNDCTL_DSP_SPEED*                              | 0xC0045002 |
| *SCE_SPDIF_IOCTL_SNDCTL_DSP_SYNCGROUP*                          | 0xC048501C |


## `/dev/usbctl`

### IOCTLs

Partial list of IOCTL codes:

| Name                                                            | Code       |
|-----------------------------------------------------------------|------------|
| *SCE_USB_IOCTL_SNDCTL_DSP_CHANNELS*                             | 0xC0045002 |
| *SCE_USB_IOCTL_SNDCTL_DSP_GETBLKSIZE*                           | 0x40045004 |
| *SCE_USB_IOCTL_SNDCTL_DSP_SETFMT*                               | 0x40045005 |
| *SCE_USB_IOCTL_SNDCTL_DSP_SETFRAGMENT*                          | 0x00000001 |
| *SCE_USB_IOCTL_SNDCTL_DSP_SPEED*                                | 0xC0045002 |
| *SCE_USB_IOCTL_SOUND_PCM_READ_BITS*                             | 0x40045005 |
| *SCE_USB_IOCTL_SOUND_PCM_READ_RATE*                             | 0x40045002 |


## Unknown

### IOCTLs

Partial list of IOCTL codes:

| Name                                                            | Code       |
|-----------------------------------------------------------------|------------|
| *SETFRAGMENT*                                                   | 0x80045010 |
| *SUBMIT_IB*                                                     | *???*      |
| *CAMGETPASSTHRU*                                                | 0x00000800 |
| *CAMIOCOMMAND*                                                  | 0x00000800 |
| *CAMIOCOMMAND*                                                  | 0xC4A81602 |
| *DIOCGMEDIASIZE*                                                | 0x40086481 |
| *DIOCGSECTORSIZE*                                               | 0x40046480 |
| *FIOGETDATACHUNKS*                                              | 0xC03866A7 |
| *GETBLKSIZE*                                                    | 0x80045010 |
