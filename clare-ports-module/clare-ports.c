// SPDX-License-Identifier: GPL-2.0-or-later
/* clare-ports.c
 *
 * CLARE-Hypervisor inter-domain ports
 *
 * Copyright (C) 2020 Accelerat.
 */

#include <linux/types.h>
#include <linux/poll.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/arm-smccc.h>

/* ----------------------------------------------------------------------------- */

MODULE_AUTHOR("Accelerat developers");
MODULE_DESCRIPTION("CLARE kernel module for inter-domain ports");
MODULE_LICENSE("GPL v2");

/* ----------------------------------------------------------------------------- */

#define HYPERCALL_ID				(0x8600F005)

/* ----------------------------------------------------------------------------- */

#define MAX_NUM_OF_PORTS			(32)
#define PORT_NULL_ID				(255)
#define PORT_PATH_SIZE				(32)
#define PORT_NAME_SIZE				(32)
#define PORT_DEV_NAME_SIZE			(PORT_PATH_SIZE + PORT_NAME_SIZE + 1)

/* ----------------------------------------------------------------------------- */

/* Do not edit or remove this entry */
enum hyp_api_result {
	P_OK = 0,
	P_ADDRESS_ERROR,
	P_PARAMETERS_ERROR,
	P_READ_PERMISSION_ERROR,
	P_WRITE_PERMISSION_ERROR,
	P_PORT_EMPTY,
	P_PORT_FULL,
	P_PORT_IMPLEMENTATION_ERROR,
	P_TOO_MANY_WRITERS_CONCURRENTLY,
	P_TOO_MANY_READERS_CONCURRENTLY,
	P_LAST_ERROR_CODE
};

/* Do not edit or remove this entry */
enum hyp_port_type {
	SAMPLING_PORT = 0,
	QUEUING_PORT,
};

/* Do not edit or remove this entry */
enum hyp_vm_comm_ops {
	SAMPLING_PORT_CREATION = 0,
	SAMPLING_PORT_READ,
	SAMPLING_PORT_WRITE,
	SAMPLING_PORT_CLEAN,
	SAMPLING_PORT_HOW_MANY,
	SAMPLING_PORT_GET_EXT_ID,
	SAMPLING_PORT_GET_NAME,
	QUEUING_PORT_CREATE,
	QUEUING_PORT_READ,
	QUEUING_PORT_WRITE,
	QUEUING_PORT_HOW_MANY,
	QUEUING_PORT_GET_EXT_ID,
	QUEUING_PORT_GET_NAME,
	LAST_OPERATION_ID
};

/* ----------------------------------------------------------------------------- */

struct clare_port_hyp_ops {
	enum hyp_vm_comm_ops get_how_many;
	enum hyp_vm_comm_ops get_name;
	enum hyp_vm_comm_ops get_ext_id;
	enum hyp_vm_comm_ops create;
	enum hyp_vm_comm_ops read;
	enum hyp_vm_comm_ops write;
};

struct clare_port {
	u64 id;
	char name[PORT_NAME_SIZE];
	char dev_name[PORT_DEV_NAME_SIZE];
	const struct clare_port_hyp_ops *hyp_ops;
	bool active;
	struct mutex m_lock;
	struct miscdevice misc_cdev;
};

struct clare_ports {
	struct clare_port *ports_array[MAX_NUM_OF_PORTS];
	u64 num_ports;
	const struct clare_port_hyp_ops hyp_ops;
	const enum hyp_port_type type;
	const char *class_name;
	const char *dev_base_name;
};

/* ----------------------------------------------------------------------------- */

static struct clare_ports sampling_ports = {
	.hyp_ops = {
		.get_how_many = SAMPLING_PORT_HOW_MANY,
		.get_name = SAMPLING_PORT_GET_NAME,
		.get_ext_id = SAMPLING_PORT_GET_EXT_ID,
		.create = SAMPLING_PORT_CREATION,
		.read = SAMPLING_PORT_READ,
		.write = SAMPLING_PORT_WRITE
	},
	.type = SAMPLING_PORT,
	.class_name = "sampling",
	.dev_base_name = "clare!s_ports!"
};

static struct clare_ports queuing_ports = {
	.hyp_ops = {
		.get_how_many = QUEUING_PORT_HOW_MANY,
		.get_name = QUEUING_PORT_GET_NAME,
		.get_ext_id = QUEUING_PORT_GET_EXT_ID,
		.create = QUEUING_PORT_CREATE,
		.read = QUEUING_PORT_READ,
		.write = QUEUING_PORT_WRITE
	},
	.type = QUEUING_PORT,
	.class_name = "queuing",
	.dev_base_name = "clare!q_ports!"
};

/* ----------------------------------------------------------------------------- */

static inline enum hyp_api_result hyp_call(enum hyp_vm_comm_ops op,
									void* mailbox_addr, u64 mailbox_size)
{
	struct arm_smccc_res hvc_res;

	arm_smccc_hvc(HYPERCALL_ID, op, (u64) mailbox_addr, mailbox_size,
					0, 0, 0, 0, &hvc_res);

	return (enum hyp_api_result) hvc_res.a0;
}

static inline enum hyp_api_result hyp_call_id(enum hyp_vm_comm_ops op,
							void* mailbox_addr, u64 mailbox_size, u64 port_id)
{
	struct arm_smccc_res hvc_res;

	arm_smccc_hvc(HYPERCALL_ID, op, (u64) mailbox_addr, mailbox_size,
					port_id, 0, 0, 0, &hvc_res);

	return (enum hyp_api_result) hvc_res.a0;
}

/* ----------------------------------------------------------------------------- */

static int port_cdev_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int port_cdev_close(struct inode *inode, struct file *file)
{
	return 0;
}

static ssize_t port_cdev_read(struct file *file, char __user *ubuf,
							size_t count, loff_t *off)
{
	char *kbuf;
	struct clare_port *port;
	ssize_t retval;
	int kern_retval;
	enum hyp_api_result hyp_retval;
	
	port = container_of(file->private_data, struct clare_port, misc_cdev);

	kern_retval = mutex_lock_interruptible(&port->m_lock);
	if (kern_retval != 0) {
		retval = -ERESTARTSYS;
		goto out;
	}

	kbuf = kzalloc(count, GFP_USER);
	if (kbuf == NULL) {
		dev_err(port->misc_cdev.this_device,
			"clare ports: read: unable to allocate mem\n");
		retval = -ENOMEM;
		goto out_unlock;
	}

	hyp_retval = hyp_call_id(port->hyp_ops->read, kbuf, count, port->id);
	switch (hyp_retval) {
	case P_OK:
		retval = count;
		break;
	case P_PORT_EMPTY:
		retval = 0;
		break;
	default:
		dev_err(port->misc_cdev.this_device,
				"clare ports: %s port read: error %d on copy from clare\n",
				port->name, hyp_retval);
		retval = -EIO;
		goto out_free_unlock;
		break;
	}

	kern_retval = copy_to_user(ubuf, kbuf, count);
	if (kern_retval != 0) {
		dev_err(port->misc_cdev.this_device,
				"clare ports: %s port read: error on copy to user\n",
				port->name);
		retval = -EFAULT;
		goto out_free_unlock;
	}

out_free_unlock:
	kfree(kbuf);
out_unlock:
	mutex_unlock(&port->m_lock);
out:
	return retval;
}

static ssize_t port_cdev_write(struct file *file, const char __user *ubuf,
							size_t count, loff_t *off)
{
	char *kbuf;
	struct clare_port *port;
	ssize_t retval;
	int kern_retval;
	enum hyp_api_result hyp_retval;
	
	port = container_of(file->private_data, struct clare_port, misc_cdev);

	kern_retval = mutex_lock_interruptible(&port->m_lock);
	if (kern_retval != 0) {
		retval = -ERESTARTSYS;
		goto out;
	}
	
	kbuf = kzalloc(count, GFP_USER);
	if (kbuf == NULL) {
		dev_err(port->misc_cdev.this_device,
				"clare ports: write: unable to allocate mem\n");
		retval = -ENOMEM;
		goto out_unlock;
	}

	kern_retval = copy_from_user(kbuf, ubuf, count);
	if (kern_retval != 0) {
		dev_err(port->misc_cdev.this_device,
				"clare ports: write: error on copy from user\n");
		retval = -EFAULT;
		goto out_free_unlock;
	}

	hyp_retval = hyp_call_id(port->hyp_ops->write, kbuf, count, port->id);
	switch (hyp_retval) {
	case P_OK:
		retval = count;
		break;
	case P_PORT_FULL:
		retval = 0;
		break;
	default:
		dev_err(port->misc_cdev.this_device,
				"clare ports: %s port write: error %d on copy to clare\n",
				port->name, hyp_retval);
		retval = -EIO;
		goto out_free_unlock;
		break;
	}

out_free_unlock:
	kfree(kbuf);
out_unlock:
	mutex_unlock(&port->m_lock);
out:
	return retval;
}

/* ----------------------------------------------------------------------------- */

static const struct file_operations port_cdev_fops = {
	.owner		= THIS_MODULE,
	.read		= port_cdev_read,
	.open 		= port_cdev_open,
	.release 	= port_cdev_close,
	.write		= port_cdev_write
};

/* ----------------------------------------------------------------------------- */

static void ports_clean(struct clare_ports *ports)
{
	u64 i;

	if (ports == NULL)
		return;

	for (i = 0; i < MAX_NUM_OF_PORTS; i++) {
		if (ports->ports_array[i] != NULL && 
			ports->ports_array[i]->active == true) {
			misc_deregister(&ports->ports_array[i]->misc_cdev);
		}
	
		kfree(ports->ports_array[i]);
	}
}

static int ports_init(struct clare_ports *ports)
{
	int retval;
	enum hyp_api_result hyp_retval;
	u64 i;

	/* Get number of ports */
	hyp_retval = hyp_call(ports->hyp_ops.get_how_many, &ports->num_ports,
						sizeof (ports->num_ports));
	if (hyp_retval != P_OK) {
		pr_err("clare ports: error %d while initializing %s ports env.\n",
				hyp_retval, ports->class_name);
		retval = -EIO;
		goto out;
	}

	/* Initialize ports deices */
	for (i = 0; i < ports->num_ports; i++) {
		
		/* Initialize ports array */
		ports->ports_array[i] = kzalloc(sizeof (*ports->ports_array[i]),
									GFP_USER);
		if (ports->ports_array[i] == NULL) {
			pr_err("clare ports: cannot allocate memory.\n");
			retval = -ENOMEM;
			goto out_clean;
		}
		
		mutex_init(&ports->ports_array[i]->m_lock);
		ports->ports_array[i]->hyp_ops = &ports->hyp_ops;

		/* Get port id */
		hyp_retval = hyp_call_id(ports->hyp_ops.get_ext_id,
								&ports->ports_array[i]->id, sizeof (u64), i);
		if (hyp_retval != P_OK) {
			pr_err("clare ports: error %d while get %s port %llu ext id.\n",
				hyp_retval, ports->class_name, i);
			retval = -EIO;
			goto out_clean;
		}

		/* Get port name */
		hyp_retval = hyp_call_id(ports->hyp_ops.get_name,
								ports->ports_array[i]->name, PORT_NAME_SIZE,
								ports->ports_array[i]->id);
		if (hyp_retval != P_OK) {
			pr_err("clare ports: error %d while get %s port %llu name.\n",
				hyp_retval, ports->class_name, i);
			retval = -EIO;
			goto out_clean;
		}

		snprintf(ports->ports_array[i]->dev_name,
				sizeof (ports->ports_array[i]->dev_name),
				"%s%s", ports->dev_base_name, ports->ports_array[i]->name);
		
		/* Init port dev */
		ports->ports_array[i]->misc_cdev.minor = MISC_DYNAMIC_MINOR;
		ports->ports_array[i]->misc_cdev.name = ports->ports_array[i]->dev_name;
		ports->ports_array[i]->misc_cdev.fops = &port_cdev_fops;

		retval = misc_register(&ports->ports_array[i]->misc_cdev);
		if (retval < 0) {
			pr_err("clare ports: cannot register %s port %llu device.\n", 
				ports->class_name, i);
			goto out_clean;
		}

		ports->ports_array[i]->active = true;
	}

	retval = 0;
	goto out;

out_clean:
	ports_clean(ports);
out:
	return retval;
}

/* ----------------------------------------------------------------------------- */

static int __init clare_ports_mod_init(void)
{
	int retval;

	retval = ports_init(&sampling_ports);
	if (retval != 0)
		return retval;

	pr_info("clare ports: %llu %s ports initialized\n",
			sampling_ports.num_ports, sampling_ports.class_name);

	retval = ports_init(&queuing_ports);
	if (retval != 0) {
		ports_clean(&sampling_ports);
		return retval;
	}

	pr_info("clare ports: %llu %s ports initialized\n",
			queuing_ports.num_ports, queuing_ports.class_name);
	
	return 0;
}

static void __exit clare_ports_mod_exit(void)
{
	ports_clean(&sampling_ports);
	ports_clean(&queuing_ports);
}

/* ----------------------------------------------------------------------------- */

module_init(clare_ports_mod_init);
module_exit(clare_ports_mod_exit);
