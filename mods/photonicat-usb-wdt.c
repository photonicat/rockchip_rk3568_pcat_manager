#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/timer.h>
#include <linux/usb.h>
#include <linux/gpio.h>
#include <linux/gpio/consumer.h>
#include <linux/delay.h>
#include <linux/workqueue.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>

#define PCAT_USB_WATCHDOG_SCAN_INTERVAL_DEFAULT 15000
#define PCAT_USB_WATCHDOG_RESET_MS_DEFAULT 50

struct pcat_usb_watchdog_data {
	struct device *dev;
	int target_vid;
	int target_pid;
	u32 scan_interval;
	u32 reset_ms;
	struct gpio_desc *reset_gpio;
	bool target_live;
	struct timer_list watchdog_timer;
	struct work_struct gpio_work;
	struct notifier_block usb_nb;
};

static void pcat_usb_watchdog_gpio_work(struct work_struct *work)
{
	struct pcat_usb_watchdog_data *data = container_of(work,
		struct pcat_usb_watchdog_data, gpio_work);

	gpiod_set_value(data->reset_gpio, 1);
	msleep(data->reset_ms);
	gpiod_set_value(data->reset_gpio, 0);
}


static int pcat_usb_watchdog_usb_notify(struct notifier_block *self,
	unsigned long action, void *dev)
{
	struct pcat_usb_watchdog_data *data = container_of(self,
		struct pcat_usb_watchdog_data, usb_nb);
	struct usb_device *udev = (struct usb_device *)dev;

	if (!udev)
		return NOTIFY_OK;

	if (le16_to_cpu(udev->descriptor.idVendor) == data->target_vid &&
		le16_to_cpu(udev->descriptor.idProduct) == data->target_pid) {

		switch (action) {
		case USB_DEVICE_ADD:
			data->target_live = true;
			dev_info(data->dev, "Target device added.\n");
			break;
		case USB_DEVICE_REMOVE:
			data->target_live = false;
			dev_info(data->dev, "Target device removed!\n");
			break;
		}
	}

	return NOTIFY_OK;
}

static void pcat_usb_watchdog_timer_callback(struct timer_list *timer)
{
	struct pcat_usb_watchdog_data *data = container_of(timer,
		struct pcat_usb_watchdog_data, watchdog_timer);

	if (!data->target_live) {
		dev_warn(data->dev, "Target device is not live, triggering reset!\n");
		schedule_work(&data->gpio_work);
	}

	mod_timer(&data->watchdog_timer,
		jiffies + msecs_to_jiffies(data->scan_interval));
}

static const struct of_device_id pcat_usb_watchdog_of_match[] = {
	{ .compatible = "pcat-usb-watchdog" },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, pcat_usb_watchdog_of_match);

static int pcat_usb_watchdog_probe(struct platform_device *pdev)
{
	struct pcat_usb_watchdog_data *wdt_data;
	struct device *dev = &pdev->dev;
	u32 vid, pid;
	int ret;

	wdt_data = devm_kzalloc(dev, sizeof(*wdt_data), GFP_KERNEL);
	if (!wdt_data)
		return -ENOMEM;

	wdt_data->dev = dev;
	platform_set_drvdata(pdev, wdt_data);

	if (!of_property_read_u32(dev->of_node, "target-vid", &vid)) {
		wdt_data->target_vid = vid;
	} else {
		dev_err(dev, "No valid USB target-vid configured!\n");
		return -EINVAL;
	}

	if (!of_property_read_u32(dev->of_node, "target-pid", &pid)) {
		wdt_data->target_pid = pid;
	} else {
		dev_err(dev, "No valid USB target-pid configured!\n");
		return -EINVAL;
	}

	if (!of_property_read_u32(dev->of_node, "scan-interval",
		&wdt_data->scan_interval)) {

	} else {
		wdt_data->scan_interval = PCAT_USB_WATCHDOG_SCAN_INTERVAL_DEFAULT;
	}

	if (!of_property_read_u32(dev->of_node, "reset-ms",
		&wdt_data->reset_ms)) {

	} else {
		wdt_data->reset_ms = PCAT_USB_WATCHDOG_RESET_MS_DEFAULT;
	}

	if (wdt_data->scan_interval < 100) {
		wdt_data->scan_interval = PCAT_USB_WATCHDOG_SCAN_INTERVAL_DEFAULT;
	}

	if (wdt_data->reset_ms < 1 || wdt_data->reset_ms > 10000) {
		wdt_data->reset_ms = PCAT_USB_WATCHDOG_RESET_MS_DEFAULT;
	}

	wdt_data->reset_gpio = devm_gpiod_get(dev, "reset", GPIOD_OUT_LOW);
	if (IS_ERR(wdt_data->reset_gpio)) {
		ret = PTR_ERR(wdt_data->reset_gpio);
		dev_err(dev, "Failed to get reset GPIO: %d\n", ret);
		return ret;
	}

	INIT_WORK(&wdt_data->gpio_work, pcat_usb_watchdog_gpio_work);

	wdt_data->usb_nb.notifier_call = pcat_usb_watchdog_usb_notify;
	usb_register_notify(&wdt_data->usb_nb);

	timer_setup(&wdt_data->watchdog_timer, pcat_usb_watchdog_timer_callback, 0);

	msleep(1000);
	pcat_usb_watchdog_gpio_work(&wdt_data->gpio_work);
	
	/* Leave 30s for system startup. */
	mod_timer(&wdt_data->watchdog_timer, jiffies + msecs_to_jiffies(30000));

	dev_info(dev, "photonicat USB watchdog initialized OK.\n");

	return 0;
}

static void pcat_usb_watchdog_remove(struct platform_device *pdev)
{
	struct pcat_usb_watchdog_data *wdt_data = platform_get_drvdata(pdev);

	usb_unregister_notify(&wdt_data->usb_nb);

	del_timer_sync(&wdt_data->watchdog_timer);
	cancel_work_sync(&wdt_data->gpio_work);

	wdt_data->reset_gpio = NULL;
	wdt_data->target_live = false;
}

static struct platform_driver pcat_usb_watchdog_driver = {
	.probe = pcat_usb_watchdog_probe,
	.remove = pcat_usb_watchdog_remove,
	.driver = {
		.name = "pcat-usb-watchdog",
		.of_match_table = pcat_usb_watchdog_of_match,
	},
};

static int __init pcat_usb_watchdog_init(void)
{
	printk(KERN_INFO "usb_watchdog: Loading USB watchdog driver\n");
	return platform_driver_register(&pcat_usb_watchdog_driver);
}

static void __exit pcat_usb_watchdog_exit(void)
{
	platform_driver_unregister(&pcat_usb_watchdog_driver);
}

module_init(pcat_usb_watchdog_init);
module_exit(pcat_usb_watchdog_exit);

MODULE_AUTHOR("Kyosuke Nekoyashiki <supercatexpert@gmail.com>");
MODULE_DESCRIPTION("photonicat USB device watchdog");
MODULE_LICENSE("GPL v2");
MODULE_VERSION("1.0");
