/*
 * Portion Copyright (c) 2017 Kentaro Sekimoto
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mbed.h"
#include "https_request.h"
#ifdef TARGET_GR_LYCHEE
#include "ESP32Interface.h"
#else
#include "ESP8266Interface.h"
#endif
#include "twitter.h"
#include "twitter_conf.h"
//#include "sample-jpg.h"
#include "EasyAttach_CameraAndLCD.h"
#include "SdUsbConnect.h"
#include "JPEG_Converter.h"
#include "dcache-control.h"

//#define SAVE_TO_STRORAGE
//#define MBED_CONF_APP_LCD 1

#ifdef TARGET_GR_LYCHEE
char tweet_str[] = "Tweet with image from MBED GR-LYCHEE Camera";
#else
char tweet_str[] = "Tweet with image from MBED GR-PEACH";
#endif

#define MOUNT_NAME             "storage"

/*! Frame buffer stride: Frame buffer stride should be set to a multiple of 32 or 128
    in accordance with the frame buffer burst transfer mode. */
#ifdef TARGET_GR_LYCHEE
#define VIDEO_PIXEL_HW         (480u)  /*  */
#define VIDEO_PIXEL_VW         (272u)  /*  */
#else
#define VIDEO_PIXEL_HW         (640u)  /* VGA */
#define VIDEO_PIXEL_VW         (480u)  /* VGA */
#endif
#define FRAME_BUFFER_STRIDE    (((VIDEO_PIXEL_HW * 2) + 31u) & ~31u)
#define FRAME_BUFFER_HEIGHT    (VIDEO_PIXEL_VW)

#if defined(__ICCARM__)
#pragma data_alignment=32
static uint8_t user_frame_buffer0[FRAME_BUFFER_STRIDE * FRAME_BUFFER_HEIGHT]@ ".mirrorram";
#else
static uint8_t user_frame_buffer0[FRAME_BUFFER_STRIDE * FRAME_BUFFER_HEIGHT]__attribute((section("NC_BSS"),aligned(32)));
#endif
static int file_name_index = 1;
static volatile int Vfield_Int_Cnt = 0;
/* jpeg convert */
static JPEG_Converter Jcu;
#if defined(__ICCARM__)
#pragma data_alignment=32
static uint8_t JpegBuffer[1024 * 63];
#else
static uint8_t JpegBuffer[1024 * 63]__attribute((aligned(32)));
#endif

DisplayBase Display;
DigitalIn   button0(USER_BUTTON0);
DigitalOut  led1(LED1);

static void IntCallbackFunc_Vfield(DisplayBase::int_type_t int_type) {
    if (Vfield_Int_Cnt > 0) {
        Vfield_Int_Cnt--;
    }
}

static void wait_new_image(void) {
    Vfield_Int_Cnt = 1;
    while (Vfield_Int_Cnt > 0) {
        Thread::wait(1);
    }
}

static void Start_Video_Camera(void) {
    // Initialize the background to black
    for (uint32_t i = 0; i < sizeof(user_frame_buffer0); i += 2) {
        user_frame_buffer0[i + 0] = 0x10;
        user_frame_buffer0[i + 1] = 0x80;
    }

    // Field end signal for recording function in scaler 0
    Display.Graphics_Irq_Handler_Set(DisplayBase::INT_TYPE_S0_VFIELD, 0, IntCallbackFunc_Vfield);

    // Video capture setting (progressive form fixed)
    Display.Video_Write_Setting(
        DisplayBase::VIDEO_INPUT_CHANNEL_0,
        DisplayBase::COL_SYS_NTSC_358,
        (void *)user_frame_buffer0,
        FRAME_BUFFER_STRIDE,
        DisplayBase::VIDEO_FORMAT_YCBCR422,
        DisplayBase::WR_RD_WRSWA_32_16BIT,
        VIDEO_PIXEL_VW,
        VIDEO_PIXEL_HW
    );
    EasyAttach_CameraStart(Display, DisplayBase::VIDEO_INPUT_CHANNEL_0);
}

#if MBED_CONF_APP_LCD
static void Start_LCD_Display(void) {
    DisplayBase::rect_t rect;

    rect.vs = 0;
    rect.vw = VIDEO_PIXEL_VW;
    rect.hs = 0;
    rect.hw = VIDEO_PIXEL_HW;
    Display.Graphics_Read_Setting(
        DisplayBase::GRAPHICS_LAYER_0,
        (void *)user_frame_buffer0,
        FRAME_BUFFER_STRIDE,
        DisplayBase::GRAPHICS_FORMAT_YCBCR422,
        DisplayBase::WR_RD_WRSWA_32_16BIT,
        &rect
    );
    Display.Graphics_Start(DisplayBase::GRAPHICS_LAYER_0);

    Thread::wait(50);
    EasyAttach_LcdBacklight(true);
}
#endif

size_t jcu_encode_size = 0;
static void save_image_jpg(void) {
    JPEG_Converter::bitmap_buff_info_t bitmap_buff_info;
    JPEG_Converter::encode_options_t   encode_options;

    bitmap_buff_info.width              = VIDEO_PIXEL_HW;
    bitmap_buff_info.height             = VIDEO_PIXEL_VW;
    bitmap_buff_info.format             = JPEG_Converter::WR_RD_YCbCr422;
    bitmap_buff_info.buffer_address     = (void *)user_frame_buffer0;

    encode_options.encode_buff_size     = sizeof(JpegBuffer);
    encode_options.p_EncodeCallBackFunc = NULL;
    encode_options.input_swapsetting    = JPEG_Converter::WR_RD_WRSWA_32_16_8BIT;

    dcache_invalid(JpegBuffer, sizeof(JpegBuffer));
    if (Jcu.encode(&bitmap_buff_info, JpegBuffer, &jcu_encode_size, &encode_options) == JPEG_Converter::JPEG_CONV_OK) {
        printf("Encoded to jpeg\r\n");
#ifdef SAVE_TO_STRORAGE
        char file_name[32];
        sprintf(file_name, "/"MOUNT_NAME"/img_%d.jpg", file_name_index++);
        FILE * fp = fopen(file_name, "w");
        fwrite(JpegBuffer, sizeof(char), (int)jcu_encode_size, fp);
        fclose(fp);
        printf("Saved file %s\r\n", file_name);
#endif
    }
}

#ifdef TARGET_GR_LYCHEE
ESP32Interface wifi(P5_3, P3_14, P7_1, P0_1);
#else
ESP8266Interface wifi(D1, D0);
#endif
Serial pc(USBTX, USBRX);

static void twitter_upload(char *tweet_str, char *jpeg_buf, int jpeg_size)
{
    char media_id_string[20];
    Twitter twitter(&wifi);
    twitter.set_keys((char *)CONSUMER_KEY,
            (char *)CONSUMER_SECRET,
            (char *)ACCESS_TOKEN,
            (char *)ACCESS_TOKEN_SECRET);
#ifdef TARGET_GR_LYCHEE
    twitter.upload_and_statuses_update(tweet_str, media_id_string, jpeg_buf, jpeg_size);
#else
    twitter.statuses_update(tweet_str, "");
#endif
}

int main()
{
    //pc.baud(115200);
    pc.baud(9600);

    EasyAttach_Init(Display);
    Start_Video_Camera();
#if MBED_CONF_APP_LCD
    Start_LCD_Display();
#endif

#ifdef SAVE_TO_STRORAGE
    SdUsbConnect storage(MOUNT_NAME);
#endif

    printf("\nConnecting...\n");
    printf("Waiting for about 10s\n");
    int ret = wifi.connect(MBED_CONF_APP_WIFI_SSID, MBED_CONF_APP_WIFI_PASSWORD,
            NSAPI_SECURITY_WPA_WPA2);
    if (ret != 0) {
        printf("\nConnection error\n");
        printf("\nPlease check SSID/PASSWORD in mbed_app.json\n");
        return -1;
    }
    printf("Success\n\n");
    printf("MAC: %s\n", wifi.get_mac_address());
    printf("IP: %s\n", wifi.get_ip_address());
    printf("Netmask: %s\n", wifi.get_netmask());
    printf("Gateway: %s\n", wifi.get_gateway());
    printf("RSSI: %d\n\n", wifi.get_rssi());
    printf("Puch switch 0 to capture image and upload to twitter\n");

    while (1) {
#ifdef SAVE_TO_STRORAGE
        storage.wait_connect();
#endif
        if (button0 == 0) {
            wait_new_image(); // wait for image input
            led1 = 1;
            save_image_jpg(); // save as jpeg
            led1 = 0;
            twitter_upload((char *)tweet_str, (char *)JpegBuffer, (int)jcu_encode_size);
        }
    }
    Thread::wait(osWaitForever);
}

