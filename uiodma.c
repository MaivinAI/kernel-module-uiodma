// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 Amazon, Inc or one of its affiliates
 */

/* This driver purposely does not declare any device IDs so it has to be
 * manually bound:
 *
 * echo "1e58 0001" > /sys/bus/pci/drivers/uiodma/new_id
 */

#include <linux/device.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/sysfs.h>

#define DEFAULT_UIODMA_SIZE (4 * SZ_1M)

struct uiodma {
	void *hostptr;
	dma_addr_t dmaaddr;
};

static ssize_t uiodma_dmaaddr_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct uiodma *uiodma = pci_get_drvdata(pdev);

	return scnprintf(buf, PAGE_SIZE, "%llx\n", uiodma->dmaaddr);
}

DEVICE_ATTR_RO(uiodma_dmaaddr);

static int uiodma_mmap(struct file *file, struct kobject *kobj,
		struct bin_attribute *attr, struct vm_area_struct *vma)
{
	struct pci_dev *pdev = to_pci_dev(kobj_to_dev(kobj));
	struct uiodma *uiodma = pci_get_drvdata(pdev);

	return dma_mmap_coherent(&pdev->dev, vma, uiodma->hostptr, uiodma->dmaaddr,
		vma->vm_end - vma->vm_start);
}

static const struct attribute *uiodma_attrs[] = {
	&dev_attr_uiodma_dmaaddr.attr,
	NULL,
};

static const struct bin_attribute uiodma_bin_attr = {
	.attr = {
		.name = "uiodma",
		.mode = 0600,
	},
	.size = DEFAULT_UIODMA_SIZE,
	.mmap = uiodma_mmap,
};

static int uiodma_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct uiodma *uiodma;
	int ret;

	ret = pci_enable_device(pdev);
	if (ret) {
		dev_err(&pdev->dev, "Could not enable the PCI device: %d\n",
			ret);
		return ret;
	}

	uiodma = kzalloc(sizeof(*uiodma), GFP_KERNEL);
	if (!uiodma) {
		pci_disable_device(pdev);
		return -ENOMEM;
	}

	uiodma->hostptr = dma_alloc_coherent(&pdev->dev, DEFAULT_UIODMA_SIZE,
		&uiodma->dmaaddr, GFP_KERNEL);

	if (!uiodma->hostptr) {
		dev_err(&pdev->dev, "Couldn't allocate the DMA memory\n");
		kfree(uiodma);
		pci_disable_device(pdev);
		return -ENOMEM;
	}

	if (sysfs_create_files(&pdev->dev.kobj, uiodma_attrs))
		dev_err(&pdev->dev, "Couldn't create the sysfs file\n");

	if (sysfs_create_bin_file(&pdev->dev.kobj, &uiodma_bin_attr))
		dev_err(&pdev->dev, "Couldn't create the uiodma file\n");

	pci_set_drvdata(pdev, uiodma);
	return 0;
}

static void uiodma_remove(struct pci_dev *pdev)
{
	struct uiodma *uiodma = pci_get_drvdata(pdev);

	sysfs_remove_files(&pdev->dev.kobj, uiodma_attrs);
	printk("removed file\n");

	sysfs_remove_bin_file(&pdev->dev.kobj, &uiodma_bin_attr);
	printk("removed bin file\n");

	dma_free_attrs(&pdev->dev, DEFAULT_UIODMA_SIZE,
		uiodma->hostptr, uiodma->dmaaddr, 0);

	kfree(uiodma);

	pci_disable_device(pdev);
}

static struct pci_driver uiodma_driver = {
	.name = "uiodma",
	.id_table = NULL,
	.probe = uiodma_probe,
	.remove = uiodma_remove,
};

module_pci_driver(uiodma_driver);
MODULE_LICENSE("GPL v2");
