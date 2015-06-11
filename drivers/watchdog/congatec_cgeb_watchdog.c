/*
 * CGEB watchdog driver
 *
 * (c) 2011 Sascha Hauer, Pengutronix
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/watchdog.h>
#include <linux/mfd/congatec-cgeb.h>

#define CGOS_WDOG_MODE_REBOOT_PC    0
#define CGOS_WDOG_MODE_RESTART_OS   1
#define CGOS_WDOG_MODE_STAGED    0x80

#define CGOS_WDOG_OPMODE_DISABLED      0
#define CGOS_WDOG_OPMODE_ONETIME_TRIG  1
#define CGOS_WDOG_OPMODE_SINGLE_EVENT  2
#define CGOS_WDOG_OPMODE_EVENT_REPEAT  3

#define CGOS_WDOG_EVENT_INT 0  /* NMI/IRQ */
#define CGOS_WDOG_EVENT_SCI 1  /* SMI/SCI */
#define CGOS_WDOG_EVENT_RST 2  /* system reset */
#define CGOS_WDOG_EVENT_BTN 3  /* power button */

#define CGOS_WDOG_EVENT_MAX_STAGES 3

struct cgeb_watchdog_stage {
	unsigned long timeout;
	unsigned long event;
};

struct cgeb_watchdog_config {
	unsigned long size;
	unsigned long timeout; /* not used in staged mode */
	unsigned long delay;
	unsigned long mode;
	/* optional parameters for staged watchdog */
	unsigned long op_mode;
	unsigned long stage_count;
	struct cgeb_watchdog_stage stages[CGOS_WDOG_EVENT_MAX_STAGES];
};

struct cgeb_watchdog_priv {
	struct cgeb_board_data  *board;
	struct watchdog_device  wdd;
	unsigned int            timeout_s;
	int unit;
};

static struct watchdog_info cgeb_wdd_info = {
	.options = WDIOF_SETTIMEOUT | WDIOF_KEEPALIVEPING,
	.firmware_version = 0,
	.identity = "cgeb watchdog",
};

static unsigned int watchdog_set_config(struct cgeb_watchdog_priv *priv,
		unsigned int timeout_s)
{
	struct cgeb_board_data *board = priv->board;
	struct cgeb_watchdog_config wdi;
	struct cgeb_function_parameters fps;

	memset(&wdi, 0, sizeof(wdi));
	memset(&fps, 0, sizeof(fps));

	fps.unit = priv->unit;
	fps.iptr = &wdi;

	wdi.timeout = timeout_s * 1000;
	wdi.delay = 0;
	wdi.size = sizeof(wdi);
	wdi.mode = CGOS_WDOG_MODE_REBOOT_PC;

	return cgeb_call(board, &fps, CgebWDogSetConfig);
}

static int cgeb_watchdog_start(struct watchdog_device *wdd)
{
	struct cgeb_watchdog_priv *priv = watchdog_get_drvdata(wdd);

	return watchdog_set_config(priv, priv->timeout_s);
}

static int cgeb_watchdog_stop(struct watchdog_device *wdd)
{
	struct cgeb_watchdog_priv *priv = watchdog_get_drvdata(wdd);

	return watchdog_set_config(priv, 0);
}

static int cgeb_watchdog_set_timeout(struct watchdog_device *wdd,
		unsigned int timeout_s)
{
	struct cgeb_watchdog_priv *priv = watchdog_get_drvdata(wdd);

	if (!timeout_s)
		return -EINVAL;

	priv->timeout_s = timeout_s;

	return 0;
}

struct watchdog_ops cgeb_watchdog_ops = {
	.start = cgeb_watchdog_start,
	.stop = cgeb_watchdog_stop,
	.set_timeout = cgeb_watchdog_set_timeout,
};

static int cgeb_watchdog_probe(struct platform_device *pdev)
{
	struct cgeb_watchdog_priv *priv;
	struct cgeb_pdata *pdata = pdev->dev.platform_data;
	int ret;

	dev_info(&pdev->dev, "registering\n");

	priv = devm_kzalloc(&pdev->dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	priv->wdd.ops = &cgeb_watchdog_ops;
	priv->wdd.info = &cgeb_wdd_info;
	priv->wdd.min_timeout = 1;
	priv->wdd.max_timeout = 3600;
	priv->board = pdata->board;
	priv->unit = pdata->unit;

	watchdog_set_drvdata(&priv->wdd, priv);
	platform_set_drvdata(pdev, priv);

	ret = watchdog_register_device(&priv->wdd);
	if (ret)
		return ret;

	return 0;
}

static int cgeb_watchdog_remove(struct platform_device *pdev)
{
	struct cgeb_watchdog_priv *priv = platform_get_drvdata(pdev);

	watchdog_unregister_device(&priv->wdd);

	return 0;
}

static struct platform_driver cgeb_watchdog_driver = {
	.probe          = cgeb_watchdog_probe,
	.remove         = __exit_p(cgeb_watchdog_remove),
	.driver = {
		.name   = "cgeb-watchdog",
		.owner  = THIS_MODULE,
	},
};

static int __init cgeb_watchdog_driver_init(void)
{
	return platform_driver_register(&cgeb_watchdog_driver);
}

static void __exit cgeb_watchdog_driver_exit(void)
{
	platform_driver_unregister(&cgeb_watchdog_driver);
}

module_init(cgeb_watchdog_driver_init);
module_exit(cgeb_watchdog_driver_exit);

MODULE_AUTHOR("Sascha Hauer <s.hauer@pengutronix.de>");
MODULE_DESCRIPTION("cgeb watchdog driver");
MODULE_LICENSE("GPL");
