#include <linux/cdev.h>
#include <linux/fs.h>

struct counter {
	volatile unsigned char ctr;
	struct cdev cdev;
} counter;

MODULE_LICENSE("GPL");

static int dev_counter_open(struct inode *inode, struct file *file)
{
	struct counter *ctr = container_of(inode->i_cdev, struct counter, cdev);

	printk("counter[%d] open\n", ctr->ctr);

	file->private_data = ctr;

	return 0;
}

static ssize_t dev_counter_read(struct file *file, char __user *ubuf,
				size_t size, loff_t *ppos)
{
	int i, ret;
	struct counter *ctr = file->private_data;
	unsigned char *kbuf;

	printk("counter[%d] read %ld (before)\n", ctr->ctr, size);

	kbuf = kmalloc(size, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	for (i = 0; i < size; i++)
		kbuf[i] = ctr->ctr++;

	printk("counter[%d] read %ld (after)\n", ctr->ctr, size);

	ret = copy_to_user(ubuf, kbuf, size);
	kfree(kbuf);
	if (ret)
		return -EFAULT;

	return size;
}

static ssize_t dev_counter_write(struct file *file, const char __user *ubuf,
				 size_t size, loff_t *ppos)
{
	struct counter *ctr = file->private_data;
	printk("counter[%d] write %ld (ignore)\n", ctr->ctr, size);
	return size;
}

static long dev_counter_unlocked_ioctl(struct file *file, unsigned int cmd,
				       unsigned long arg)
{
	struct counter *ctr = file->private_data;

	printk("counter[%d] ioctl %d\n", ctr->ctr, cmd);

	if (cmd != 0x1234)
		return -EFAULT;

	ctr->ctr = arg;
	printk("counter[%d] cleared to %ld\n", ctr->ctr, arg);
	return 0;
}

static const struct file_operations counter_operations = {
	.owner = THIS_MODULE,
	.open = dev_counter_open,
	.read = dev_counter_read,
	.write = dev_counter_write,
	.unlocked_ioctl = dev_counter_unlocked_ioctl,
};

dev_t devno;
struct class *cls;
struct device *dev;

int __init dev_counter_init(void)
{
	int ret;

	printk("counter init\n");

	counter.ctr = 0;
	ret = alloc_chrdev_region(&devno, 0, 1, "counter");
	if (ret < 0) {
		printk("failed to alloc_chrdev_region\n");
		goto err_register_chrdev_region;
	}

	cls = class_create(THIS_MODULE, "counter");
	if (IS_ERR(cls)) {
		ret = PTR_ERR(cls);
		printk("failed to class_create\n");
		goto err_class_create;
	}

	cdev_init(&counter.cdev, &counter_operations);
	ret = cdev_add(&counter.cdev, devno, 1);
	if (ret < 0)
		goto err_cdev_add;

	dev = device_create(cls, NULL, devno, NULL, "dev_counter%d", 0);
	if (IS_ERR(dev)) {
		ret = PTR_ERR(dev);
		printk("failed to device_create\n");
		goto err_device_create;
	}

	printk("counter regitered\n");
	return 0;

err_device_create:
	device_destroy(cls, devno);
err_cdev_add:
	cdev_del(&counter.cdev);
err_class_create:
	unregister_chrdev_region(devno, 1);
err_register_chrdev_region:
	return ret;
}

void __exit dev_counter_exit(void)
{
	printk("counter exit\n");
	device_destroy(cls, devno);
	class_destroy(cls);
	cdev_del(&counter.cdev);
	unregister_chrdev_region(devno, 1);
}

module_init(dev_counter_init);
module_exit(dev_counter_exit);
