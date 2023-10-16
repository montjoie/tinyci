/* Ethernet Basic Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_netif.h"
#include "esp_eth.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "driver/gpio.h"
#include "sdkconfig.h"
#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include <lwip/netdb.h>
#include <apps/ping/ping_sock.h>

static const char *TAG = "tinyci-fw";
static bool has_ip;
static int net_timeout;
static int ping_status;
static esp_ping_handle_t ping;

#define ETH_MDC_GPIO		23
#define ETH_MDIO_GPIO		18
#define ETH_PHY_RST_GPIO	16
#define ETH_PHY_ADDR 		1

static void test_on_ping_success(esp_ping_handle_t hdl, void *args)
{
    uint8_t ttl;
    uint16_t seqno;
    uint32_t elapsed_time, recv_len;
    ip_addr_t target_addr;
    esp_ping_get_profile(hdl, ESP_PING_PROF_SEQNO, &seqno, sizeof(seqno));
    esp_ping_get_profile(hdl, ESP_PING_PROF_TTL, &ttl, sizeof(ttl));
    esp_ping_get_profile(hdl, ESP_PING_PROF_IPADDR, &target_addr, sizeof(target_addr));
    esp_ping_get_profile(hdl, ESP_PING_PROF_SIZE, &recv_len, sizeof(recv_len));
    esp_ping_get_profile(hdl, ESP_PING_PROF_TIMEGAP, &elapsed_time, sizeof(elapsed_time));
    printf("%ld bytes from %s icmp_seq=%d ttl=%d time=%ld ms\n",
           recv_len, inet_ntoa(target_addr.u_addr.ip4), seqno, ttl, elapsed_time);
    esp_ping_stop(&ping);
    ping_status = 1;
}

static void test_on_ping_timeout(esp_ping_handle_t hdl, void *args)
{
    uint16_t seqno;
    ip_addr_t target_addr;
    esp_ping_get_profile(hdl, ESP_PING_PROF_SEQNO, &seqno, sizeof(seqno));
    esp_ping_get_profile(hdl, ESP_PING_PROF_IPADDR, &target_addr, sizeof(target_addr));
    printf("From %s icmp_seq=%d timeout\n", inet_ntoa(target_addr.u_addr.ip4), seqno);
    esp_ping_stop(&ping);
    ping_status = 1;
}

static void test_on_ping_end(esp_ping_handle_t hdl, void *args)
{
    uint32_t transmitted;
    uint32_t received;
    uint32_t total_time_ms;

    esp_ping_get_profile(hdl, ESP_PING_PROF_REQUEST, &transmitted, sizeof(transmitted));
    esp_ping_get_profile(hdl, ESP_PING_PROF_REPLY, &received, sizeof(received));
    esp_ping_get_profile(hdl, ESP_PING_PROF_DURATION, &total_time_ms, sizeof(total_time_ms));
    printf("%ld packets transmitted, %ld received, time %ldms\n", transmitted, received, total_time_ms);
    esp_ping_stop(&ping);
    ping_status = 1;
}

# define PING_INTERVAL 500
static void doping() {
	int err;

	if (!has_ip) {
        	ESP_LOGI(TAG, "Cannot ping, no net");
		net_timeout++;
		return;
	}
	if (ping_status == 0)
		goto ping_init;
	if (ping_status < PING_INTERVAL) {
		ping_status ++;
		return;
	}
	if (ping_status >= PING_INTERVAL) {
		esp_ping_start(ping);
		return;
	}
ping_init:
	ip_addr_t target_addr;
	struct addrinfo hint;
	struct addrinfo *res = NULL;
	memset(&hint, 0, sizeof(hint));
	memset(&target_addr, 0, sizeof(target_addr));
	getaddrinfo("192.168.1.1", NULL, &hint, &res);
	struct in_addr addr4 = ((struct sockaddr_in *) (res->ai_addr))->sin_addr;
	inet_addr_to_ip4addr(ip_2_ip4(&target_addr), &addr4);
	freeaddrinfo(res);
	esp_ping_config_t ping_config = ESP_PING_DEFAULT_CONFIG();
	ping_config.target_addr = target_addr;

	esp_ping_callbacks_t cbs;
	cbs.on_ping_success = test_on_ping_success;
	cbs.on_ping_timeout = test_on_ping_timeout;
	cbs.on_ping_end = test_on_ping_end;
	cbs.cb_args = "foo";
	/*cbs.cb_args = eth_event_group;*/

	err = esp_ping_new_session(&ping_config, &cbs, &ping);
	printf("PING ERR=%d\n", err);
	ping_status = 1;
}

/** Event handler for Ethernet events */
static void eth_event_handler(void *arg, esp_event_base_t event_base,
                              int32_t event_id, void *event_data)
{
    uint8_t mac_addr[6] = {0};
    /* we can get the ethernet driver handle from event data */
    esp_eth_handle_t eth_handle = *(esp_eth_handle_t *)event_data;

    switch (event_id) {
    case ETHERNET_EVENT_CONNECTED:
        esp_eth_ioctl(eth_handle, ETH_CMD_G_MAC_ADDR, mac_addr);
        ESP_LOGI(TAG, "Ethernet Link Up");
        ESP_LOGI(TAG, "Ethernet HW Addr %02x:%02x:%02x:%02x:%02x:%02x",
                 mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
        break;
    case ETHERNET_EVENT_DISCONNECTED:
        ESP_LOGI(TAG, "Ethernet Link Down");
        break;
    case ETHERNET_EVENT_START:
        ESP_LOGI(TAG, "Ethernet Started");
        break;
    case ETHERNET_EVENT_STOP:
        ESP_LOGI(TAG, "Ethernet Stopped");
        break;
    default:
        break;
    }
}

/** Event handler for IP_EVENT_ETH_GOT_IP */
static void got_ip_event_handler(void *arg, esp_event_base_t event_base,
                                 int32_t event_id, void *event_data)
{
    ip_event_got_ip_t *event = (ip_event_got_ip_t *) event_data;
    const esp_netif_ip_info_t *ip_info = &event->ip_info;

    ESP_LOGI(TAG, "Ethernet Got IP Address");
    ESP_LOGI(TAG, "~~~~~~~~~~~");
    ESP_LOGI(TAG, "ETHIP:" IPSTR, IP2STR(&ip_info->ip));
    ESP_LOGI(TAG, "ETHMASK:" IPSTR, IP2STR(&ip_info->netmask));
    ESP_LOGI(TAG, "ETHGW:" IPSTR, IP2STR(&ip_info->gw));
    ESP_LOGI(TAG, "~~~~~~~~~~~");
    has_ip = 1;
}

#define NUM_RELAYS	4

static unsigned int relays_gpio_map[NUM_RELAYS] = {
	[0] = 2,
	[1] = 4,
	[2] = 14,
	[3] = 15,
};

static void reply_str(int sock, struct sockaddr_in6 *source_addr, bool ok)
{
	char nok_reply[4] = "NOK";
	char *reply = nok_reply;

	if (ok)
		reply = &nok_reply[1];

	int err = sendto(sock, reply, strlen(reply)+1, 0, (struct sockaddr *)source_addr, sizeof(*source_addr));
	if (err < 0)
		ESP_LOGE(TAG, "Error occurred during sending: errno %d", errno);
}

static bool relay_ctrl(char *cmd)
{
	unsigned int num = cmd[3] - '0';
	bool enable = false;

	if (!strncmp(cmd, "PWR", 3))
		enable = true;

	if (num >= NUM_RELAYS)
		return false;
	
	ESP_LOGI(TAG, "%sabling Relay %d (GPIO %d)", (enable?"En":"Dis"), num, relays_gpio_map[num]);

	gpio_set_level(relays_gpio_map[num], enable);

	return true;
}

static void handle_cmd(int sock, struct sockaddr_in6 *source_addr,
		       char *rx_buffer, unsigned int len)
{
	char addr_str[128];

	// Get the sender's ip address as string
	if (source_addr->sin6_family == PF_INET) {
		inet_ntoa_r(((struct sockaddr_in *)source_addr)->sin_addr.s_addr, addr_str, sizeof(addr_str) - 1);
	} else if (source_addr->sin6_family == PF_INET6) {
		inet6_ntoa_r(source_addr->sin6_addr, addr_str, sizeof(addr_str) - 1);
	}

	ESP_LOGI(TAG, "Received %d bytes from %s:", len, addr_str);
	ESP_LOGI(TAG, "%s", rx_buffer);

	if (!strncmp(rx_buffer, "VERSION", 7)) {
		char reply[128];

		sprintf(reply, "TINYCI %s", IDF_VER);
		int err = sendto(sock, reply, strlen(reply)+1, 0, (struct sockaddr *)source_addr, sizeof(*source_addr));
		if (err < 0)
			ESP_LOGE(TAG, "Error occurred during sending: errno %d", errno);
		return;
	}

	if (!strncmp(rx_buffer, "PWR", 3) || !strncmp(rx_buffer, "OFF", 3)) {
		if (relay_ctrl(rx_buffer))
			reply_str(sock, source_addr, true);
		else
			reply_str(sock, source_addr, false);
	}
	else
		reply_str(sock, source_addr, false);
}

#define PORT 1234

static void udp_server_task(void *pvParameters)
{
    char rx_buffer[10];
    int addr_family = (int)pvParameters;
    int ip_protocol = 0;
    struct sockaddr_in6 dest_addr;
    struct pollfd popol[1];

    while (1) {

        if (addr_family == AF_INET) {
            struct sockaddr_in *dest_addr_ip4 = (struct sockaddr_in *)&dest_addr;
            dest_addr_ip4->sin_addr.s_addr = htonl(INADDR_ANY);
            dest_addr_ip4->sin_family = AF_INET;
            dest_addr_ip4->sin_port = htons(PORT);
            ip_protocol = IPPROTO_IP;
        } else if (addr_family == AF_INET6) {
            bzero(&dest_addr.sin6_addr.un, sizeof(dest_addr.sin6_addr.un));
            dest_addr.sin6_family = AF_INET6;
            dest_addr.sin6_port = htons(PORT);
            ip_protocol = IPPROTO_IPV6;
        }

        int sock = socket(addr_family, SOCK_DGRAM, ip_protocol);
        if (sock < 0) {
            ESP_LOGE(TAG, "Unable to create socket: errno %d", errno);
            break;
        }

        int err = bind(sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        if (err < 0) {
            ESP_LOGE(TAG, "Socket unable to bind: errno %d", errno);
        }
        ESP_LOGI(TAG, "Socket bound, port %d", PORT);

        while (1) {
retry:
	    doping();
	    popol[0].fd = sock;
	    popol[0].events = POLLERR | POLLHUP | POLLIN | POLLPRI;
	    err = poll(popol, 1, 100);
	    if (err == -1) {
            	ESP_LOGE(TAG, "POLL ERROR\n");
		goto retry;
	    }
	    if (popol[0].revents & POLLERR) {
            	ESP_LOGE(TAG, "POLL ERR\n");
	    }
	    if (popol[0].revents & POLLPRI) {
            	ESP_LOGE(TAG, "POLL PRI\n");
	    }
	    if (popol[0].revents & POLLHUP) {
            	ESP_LOGE(TAG, "POLL HUP\n");
	    }
	    if (popol[0].revents & POLLIN) {
            	ESP_LOGE(TAG, "POLL IN\n");
		goto get;
	    }
	    goto retry;
get:
            struct sockaddr_in6 source_addr; // Large enough for both IPv4 or IPv6
            socklen_t socklen = sizeof(source_addr);
            int len = recvfrom(sock, rx_buffer, sizeof(rx_buffer) - 1, 0, (struct sockaddr *)&source_addr, &socklen);

            // Error occurred during receiving
            if (len < 0) {
                ESP_LOGE(TAG, "recvfrom failed: errno %d", errno);
                break;
            }
            // Data received
            else {

                rx_buffer[len] = 0; // Null-terminate whatever we received and treat like a string...

		handle_cmd(sock, &source_addr, rx_buffer, len);
            }
        }

        if (sock != -1) {
            ESP_LOGE(TAG, "Shutting down socket and restarting...");
            shutdown(sock, 0);
            close(sock);
        }
    }
    vTaskDelete(NULL);
}

void app_main(void)
{
    int i;
    // Setup Relays GPIO
    gpio_config_t io_conf;
    //disable interrupt
    io_conf.intr_type = GPIO_INTR_DISABLE;
    //set as output mode
    io_conf.mode = GPIO_MODE_OUTPUT;
    //bit mask of the pins that you want to set,e.g.GPIO18/19
    io_conf.pin_bit_mask = 0;
    for (i = 0 ; i < 4/*NUM_RELAYS*/ ; ++i)
	io_conf.pin_bit_mask |= 1 << relays_gpio_map[i];
    //disable pull-down mode
    io_conf.pull_down_en = 0;
    //disable pull-up mode
    io_conf.pull_up_en = 0;
    //configure GPIO with the given settings
    gpio_config(&io_conf);

    // Initialize TCP/IP network interface aka the esp-netif (should be called only once in application)
    ESP_ERROR_CHECK(esp_netif_init());
    // Create default event loop that running in background
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    esp_netif_config_t cfg = ESP_NETIF_DEFAULT_ETH();
    esp_netif_t *eth_netif = esp_netif_new(&cfg);

    // Register user defined event handers
    ESP_ERROR_CHECK(esp_event_handler_register(ETH_EVENT, ESP_EVENT_ANY_ID, &eth_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_GOT_IP, &got_ip_event_handler, NULL));

    eth_mac_config_t mac_config = ETH_MAC_DEFAULT_CONFIG();
    eth_phy_config_t phy_config = ETH_PHY_DEFAULT_CONFIG();

    eth_esp32_emac_config_t esp32_emac_config = ETH_ESP32_EMAC_DEFAULT_CONFIG();

    phy_config.phy_addr = ETH_PHY_ADDR;
    phy_config.reset_gpio_num = ETH_PHY_RST_GPIO;

    esp32_emac_config.smi_mdc_gpio_num = ETH_MDC_GPIO;
    esp32_emac_config.smi_mdio_gpio_num = ETH_MDIO_GPIO;

    esp_eth_mac_t *mac = esp_eth_mac_new_esp32(&esp32_emac_config, &mac_config);
    esp_eth_phy_t *phy = esp_eth_phy_new_lan87xx(&phy_config);
    esp_eth_config_t config = ETH_DEFAULT_CONFIG(mac, phy);
    esp_eth_handle_t eth_handle = NULL;
    ESP_ERROR_CHECK(esp_eth_driver_install(&config, &eth_handle));
    /* attach Ethernet driver to TCP/IP stack */
    ESP_ERROR_CHECK(esp_netif_attach(eth_netif, esp_eth_new_netif_glue(eth_handle)));
    /* start Ethernet driver state machine */
    ESP_ERROR_CHECK(esp_eth_start(eth_handle));

    xTaskCreate(udp_server_task, "udp_server", 4096, (void*)AF_INET6, 5, NULL);
}
