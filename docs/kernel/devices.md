# Devices

## `/dev/dce`

### IOCTLs

Partial list of IOCTL codes:

| Name                                   | Code       |
|----------------------------------------|------------|
| *SCE_SYS_DCE_IOCTL_FLIP_CONTROL*       | 0xC0308203 |


## `/dev/hdmi`

### IOCTLs

Partial list of IOCTL codes:

| Name                                   | Code       |
|----------------------------------------|------------|
| *SCE_HDMI_IOCTL_AUDIO_ASP*             | 0xC0048D18 |
| *SCE_HDMI_IOCTL_AUDIO_CONFIG*          | 0xC01C8D03 |
| *SCE_HDMI_IOCTL_AUDIO_COPY_CONTROL*    | 0xC01C8D06 |
| *SCE_HDMI_IOCTL_AUDIO_MUTE*            | 0xC0048D05 |
| *SCE_HDMI_IOCTL_CONTROL_AVOUT*         | 0xC0048D08 |
| *SCE_HDMI_IOCTL_CONTROL_HMDVIEW_MODE*  | 0xC0048D11 |
| *SCE_HDMI_IOCTL_CSC_DIRECT*            | 0xC0068D09 |
| *SCE_HDMI_IOCTL_GET_AKSV*              | 0xC0088D0F |
| *SCE_HDMI_IOCTL_GET_DP_STATE*          | 0xC0108D1A |
| *SCE_HDMI_IOCTL_GET_HDMI_CONFIG*       | 0xC0108D10 |
| *SCE_HDMI_IOCTL_GET_HDMI_STATE*        | 0xC0088D0C |
| *SCE_HDMI_IOCTL_IC_INIT*               | 0x20008D01 |
| *SCE_HDMI_IOCTL_SET_GAMUTMETA_DATA*    | 0xC0108D07 |
| *SCE_HDMI_IOCTL_VIDEO_CONFIG*          | 0xC0148D02 |


## `/dev/hmd_cmd`

### IOCTLs

Partial list of IOCTL codes:

| Name                                   | Code       |
|----------------------------------------|------------|
| *SCE_HMD_CMD_IOCTL_GET_MENU_SETTING*   | 0x8008A018 |
| *SCE_HMD_CMD_IOCTL_SET_MENU_SETTING*   | 0x8001A02D |


## `/dev/gc`

### IOCTLs

#### 0xC0108102

Seems involved in submitting PM4 command lists to the CP.
