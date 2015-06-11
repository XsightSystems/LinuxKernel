/*
 * CGEB backlight driver
 *
 * (c) 2012 Christian Gmeiner <christian.gmeiner@gmail.com>
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
#include <linux/slab.h>
#include <linux/backlight.h>
#include <linux/mfd/congatec-cgeb.h>

struct cgeb_backlight_data {
	struct cgeb_board_data          *board;
	int unit;
};

static int cgeb_backlight_update_status(struct backlight_device *bl)
{
	struct cgeb_backlight_data *data = bl_get_data(bl);
	struct cgeb_function_parameters fps;
	int brightness = bl->props.brightness;
	int err;

	memset(&fps, 0, sizeof(fps));
	
	fps.unit = data->unit;
	fps.pars[0] = brightness;
	
	err = cgeb_call(data->board, &fps, CgebVgaSetBacklight);
	return err;
}

static int cgeb_backlight_get_brightness(struct backlight_device *bl)
{
	struct cgeb_backlight_data *data = bl_get_data(bl);
	unsigned long brightness;

	cgeb_call_simple(data->board, CgebVgaGetBacklight, 0, NULL, &brightness);

	return brightness;
}

static const struct backlight_ops cgeb_backlight_ops = {
	.update_status	= cgeb_backlight_update_status,
	.get_brightness	= cgeb_backlight_get_brightness,
};

static int cgeb_backlight_probe(struct platform_device *pdev)
{  
	struct backlight_device *bl;
	struct backlight_properties props;
	struct cgeb_backlight_data *data;
	struct cgeb_pdata *pdata = pdev->dev.platform_data;
	int ret;

	data = devm_kzalloc(&pdev->dev, sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	data->unit = pdata->unit;
	data->board = pdata->board;

	props.max_brightness = 100;
	props.brightness = 100;
	props.type = BACKLIGHT_RAW;
	
	bl = backlight_device_register(dev_name(&pdev->dev), &pdev->dev, data,
					&cgeb_backlight_ops, &props);
	if (IS_ERR(bl)) {
		dev_err(&pdev->dev, "failed to register backlight\n");
		ret = PTR_ERR(bl);
		goto error_backlight_device_register;
	}

	platform_set_drvdata(pdev, bl);
	
	dev_info(&pdev->dev, "registered\n");
	return 0;
	
error_backlight_device_register:
	kfree(data);
	return ret;
};

static int cgeb_backlight_remove(struct platform_device *pdev)
{
	struct backlight_device *bl = platform_get_drvdata(pdev);
	struct cgeb_backlight_data *data = bl_get_data(bl);
	struct cgeb_function_parameters fps;

	backlight_device_unregister(bl);

	/* on module unload set brightness to 100% */
	memset(&fps, 0, sizeof(fps));
	fps.unit = data->unit;
	fps.pars[0] = 100;
	cgeb_call(data->board, &fps, CgebVgaSetBacklight);

	kfree(data);
	return 0;
}

static struct platform_driver cgeb_backlight_driver = {
	.probe          = cgeb_backlight_probe,
	.remove         = __exit_p(cgeb_backlight_remove),
	.driver = {
	        .name   = "cgeb-backlight",
	        .owner  = THIS_MODULE,
	},
};

module_platform_driver(cgeb_backlight_driver);

MODULE_AUTHOR("Christian Gmeiner <christian.gmeiner@gmail.com>");
MODULE_DESCRIPTION("cgeb backlight driver");
MODULE_LICENSE("GPL");
