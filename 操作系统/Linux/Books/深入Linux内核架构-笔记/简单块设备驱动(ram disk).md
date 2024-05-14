```c
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/fs.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/vmalloc.h>
#include <linux/types.h>
#include <linux/hdreg.h>

#define RAMHD_NAME "ramhd"
#define RAMHD_MAX_PARTITIONS 4

#define RAMHD_SECTOR_SIZE 512 
#define RAMHD_SECTORS 16 
#define RAMHD_HEADS 4
#define RAMHD_CYLINDERS 256

#define RAMHD_SECTOR_TOTAL (RAMHD_SECTORS * RAMHD_HEADS *RAMHD_CYLINDERS) 
#define RAMHD_SIZE (RAMHD_SECTOR_SIZE * RAMHD_SECTOR_TOTAL) //8mb 

typedef struct{
	uint8_t *data;
	struct request_queue *rq;
	struct gendisk *gd;
}RAMHD_DEV;

static RAMHD_DEV ramhd_dev;

static int ramhd_major;

static int ramhd_open(struct block_device* bdev, fmode_t mode)
{
	return 0;
}

static int ramhd_release(struct gendisk *gd, fmode_t mode)
{
	return 0;
}

static int ramhd_ioctl(struct block_device* bdev, fmode_t mode, unsigned int cmd, unsigned long arg)
{
	int err; 
	struct hd_geometry geo; 
	
	switch(cmd) 
	{ 
		case HDIO_GETGEO: 
	        	err = !access_ok(VERIFY_WRITE, arg, sizeof(geo)); 
		        if(err) 
				return -EFAULT; 
				            
			geo.cylinders = RAMHD_CYLINDERS; 
			geo.heads = RAMHD_HEADS; 
			geo.sectors = RAMHD_SECTORS; 
			geo.start = get_start_sect(bdev); 
								           
			if(copy_to_user((void*)arg, &geo, sizeof(geo))) 
				return -EFAULT; 
											        
			return 0;
	} 
	return -ENOTTY;
}

static struct block_device_operations ramhd_fops = {
	.owner = THIS_MODULE,
	.open = ramhd_open,
	.ioctl = ramhd_ioctl,
	.release = ramhd_release, 
};

static int ramhd_make_request(struct request_queue *rq,struct bio *bio)
{
	RAMHD_DEV *p_dev = bio->bi_bdev->bd_disk->private_data;
	char *pRHdata;
	char *pBuffer;
	struct bio_vec *bvec;
	int err = 0;
	int i;

	if(((bio->bi_sector * RAMHD_SECTOR_SIZE) + bio->bi_size) > RAMHD_SIZE){ 
		err = -EIO;
		return err;
	}

	pRHdata = p_dev->data + bio->bi_sector * RAMHD_SECTOR_SIZE;
	bio_for_each_segment(bvec,bio,i){
		pBuffer = kmap(bvec->bv_page)+bvec->bv_offset;
		switch(bio_data_dir(bio)){
			case READ:
				memcpy(pBuffer,pRHdata,bvec->bv_len);
				flush_dcache_page(bvec->bv_page);
				break;
			case WRITE:
				flush_dcache_page(bvec->bv_page);
				memcpy(pRHdata, pBuffer, bvec->bv_len); 
				break;
			default:
				kunmap(bvec->bv_page);
				goto out;
		}
		kunmap(bvec->bv_page);
		pRHdata += bvec->bv_len;
	}
out:
	bio_endio(bio,err);
	return 0;
}

static int __init simple_blk_init(void)
{
	ramhd_major = register_blkdev(0,RAMHD_NAME);//分配主设备号
	if(ramhd_major < 0){
		printk("register_blkdev error\n");
		goto reg_blk_error;
	}

	ramhd_dev.gd = alloc_disk(RAMHD_MAX_PARTITIONS);//分配gendisk
	if(ramhd_dev.gd == NULL){
		printk("alloc disk error\n");
		goto alloc_disk_error;
	}

	ramhd_dev.rq = blk_alloc_queue(GFP_KERNEL);//创建请求队列
	if(ramhd_dev.rq == NULL){
		printk("alloc request queue error\n");
		goto alloc_rq_error;
	}
	blk_queue_make_request(ramhd_dev.rq,ramhd_make_request);//关联make_request
	
	ramhd_dev.data = vmalloc(RAMHD_SIZE);//分配存储空间
	if(ramhd_dev.data == NULL){
		printk("alloc ramhd data error\n");
		goto alloc_data_error;
	}
	
	//填充gendisk数据
	ramhd_dev.gd->major = ramhd_major;
	ramhd_dev.gd->first_minor = 0;
	ramhd_dev.gd->fops = &ramhd_fops;
	ramhd_dev.gd->queue = ramhd_dev.rq;
	ramhd_dev.gd->private_data = &ramhd_dev;
	ramhd_dev.gd->flags |= GENHD_FL_SUPPRESS_PARTITION_INFO;
	strcpy(ramhd_dev.gd->disk_name, "ramhd"); 
	set_capacity(ramhd_dev.gd, RAMHD_SECTOR_TOTAL); 

	add_disk(ramhd_dev.gd); 
	
	printk("simple blk init! ramhd_major:%d\n",ramhd_major);

	return 0;
alloc_data_error:
	blk_cleanup_queue(ramhd_dev.rq);
alloc_rq_error:
	del_gendisk(ramhd_dev.gd);
	put_disk(ramhd_dev.gd);
alloc_disk_error:
	unregister_blkdev(ramhd_major,RAMHD_NAME);
reg_blk_error:
	return -1;
}

static void __exit simple_blk_exit(void)
{
	vfree(ramhd_dev.data);
	del_gendisk(ramhd_dev.gd);
	put_disk(ramhd_dev.gd);
	blk_cleanup_queue(ramhd_dev.rq);
	unregister_blkdev(ramhd_major,RAMHD_NAME);

	printk("simple blk exit\n");
}

module_init(simple_blk_init);
module_exit(simple_blk_exit);
MODULE_LICENSE("GPL");
```

参考资料:
https://m.jb51.net/article/138227.htm