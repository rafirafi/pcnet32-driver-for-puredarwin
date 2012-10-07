
/* pcnet32.c: An AMD PCnet32 ethernet driver for linux. */
/*
 *	Copyright 1996-1999 Thomas Bogendoerfer
 * 
 *	Derived from the lance driver written 1993,1994,1995 by Donald Becker.
 * 
 *	Copyright 1993 United States Government as represented by the
 *	Director, National Security Agency.
 * 
 *	This software may be used and distributed according to the terms
 *	of the GNU General Public License, incorporated herein by reference.
 *
 *	This driver is for PCnet32 and PCnetPCI based ethercards
 */

#ifndef _PCNet_H_
#define _PCNet_H_

#include <IOKit/IOLib.h>
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/network/IOEthernetController.h>
#include <IOKit/network/IOEthernetInterface.h>
#include <IOKit/network/IOGatedOutputQueue.h>
#include <IOKit/network/IOMbufMemoryCursor.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <IOKit/IOFilterInterruptEventSource.h>

extern "C"
{
	#include <sys/kpi_mbuf.h>
	#include <architecture/i386/pio.h>>
}

#include "PCNetRegs.h"
#include "kcompat.h"


#ifdef DEBUG
//#define DLog(args...)
#define DLog(args...) IOLog("PCNET: "args)
#else 
#define DLog(args...)
#endif

//Debug level >
#ifdef DEBUG
//#define DLog(args...)
#define DDLog(args...) IOLog(""args)
#else 
#define DDLog(args...)
#endif


enum
{
	MEDIUM_INDEX_10HD	= 0,
	MEDIUM_INDEX_10FD	= 1,
	MEDIUM_INDEX_AUTO	= 2,
	MEDIUM_INDEX_COUNT	= 3
};


enum 
{
    kActivationLevelNone = 0,  /* adapter shut off */
    kActivationLevelKDP,       /* adapter partially up to support KDP */
    kActivationLevelBSD        /* adapter fully up to support KDP and BSD */
};

class PCNet : public IOEthernetController
{
	OSDeclareDefaultStructors(PCNet)
public:
	virtual bool			init(OSDictionary *properties);
	virtual void			free();
	virtual bool			start(IOService *provider);
	virtual void			stop(IOService *provider);
	
	virtual IOReturn		enable(IONetworkInterface *netif);
    virtual IOReturn		disable(IONetworkInterface *netif);
	
    virtual UInt32			outputPacket(mbuf_t m, void *param);
    virtual void			getPacketBufferConstraints(IOPacketBufferConstraints *constraints) const;
    virtual IOOutputQueue	*createOutputQueue();
    virtual const OSString	*newVendorString() const;
    virtual const OSString	*newModelString() const;
    virtual IOReturn		selectMedium(const IONetworkMedium *medium);
    virtual bool			configureInterface(IONetworkInterface *netif);
    virtual bool			createWorkLoop();
    virtual IOWorkLoop		*getWorkLoop() const;
    virtual IOReturn		getHardwareAddress(IOEthernetAddress *addr);

    virtual IOReturn		setPromiscuousMode(bool enabled);
    virtual IOReturn		setMulticastMode(bool enabled);
    virtual IOReturn		setMulticastList(IOEthernetAddress *addrs, UInt32 count);

    virtual void			sendPacket(void *pkt, UInt32 pkt_len);
    virtual void			receivePacket(void * pkt, UInt32 *pkt_len, UInt32 timeout);

    virtual IOReturn		registerWithPolicyMaker(IOService *policyMaker);
    virtual IOReturn		setPowerState(UInt32 powerStateOrdinal, IOService *policyMaker);

private:
	struct pcnet32_access * access;
	
	//static struct pcnet32_access pcnet32_wio;
	//static struct pcnet32_access pcnet32_dwio;	
	
	
	UInt8 			dev_addr[6];
	
	IOSimpleLock * simpleLock;
		
	struct pcnet32_init_block *init_block;	
	IOPhysicalAddress           phys_init_block;
		
	const char		*name;
    int 			full_duplex;
	int 			options;
	
    UInt32	cur_rx, cur_tx;	/* The next free ring entry */
    UInt32	dirty_rx, dirty_tx; /* The ring entries to be free()ed. */
    UInt8	tx_full;
	
	int must_restart;
    
    //not really used, was dev-> stuff
    UInt32 last_rx;
    UInt32 trans_start;

private:
	IOPCIDevice					*pciDev;
	IOWorkLoop						*workLoop;
	IOInterruptEventSource			*intSource;
    IOTimerEventSource			*timerSource;
    IONetworkStats					*netStats;
    IOEthernetStats					*etherStats;
	IOOutputQueue					*transmitQueue;
    IOEthernetInterface				*netif;
	OSDictionary					*mediumDict;
	const IONetworkMedium			*mediumTable[MEDIUM_INDEX_COUNT];
	
	UInt16 		pioBase;
	
	// this added because of compatibility problems with new
	// init routine, OS X, on some cards, takes a crap
	// because the card recieves interrupts but isnt ready
	bool 			isInitialized;
	
	bool 			enabled;
	UInt16 		vendorId; 
	UInt16			deviceId;
	bool 			linked;
	
	UInt32			activationLevel;
	bool			enabledForBSD;
	bool			enabledForKDP;
	
	
	static int max_interrupt_work;
	



	struct	__mbuf				*Tx_skbuff[TX_RING_SIZE];// for allocatePacket freePacket	
	UInt8						*Tx_dbuff[TX_RING_SIZE];//Tx_skbuff_Md->getBytesNoCopy() 
	IOBufferMemoryDescriptor	*Tx_skbuff_Md[TX_RING_SIZE];//adress
	IOPhysicalAddress			Tx_skbuff_Dma[TX_RING_SIZE];//physical address of the Tx_skbuff_Md
	
	UInt8						*Rx_dbuff[RX_RING_SIZE];
	IOBufferMemoryDescriptor	*Rx_skbuff_Md[RX_RING_SIZE];
	IOPhysicalAddress			Rx_skbuff_Dma[RX_RING_SIZE];
	
	void *txdesc_space;
	struct pcnet32_tx_head	*TxDescArray;           /* Index of 256-alignment Tx Descriptor buffer */
	IOBufferMemoryDescriptor *tx_descMd;
	IOPhysicalAddress txdesc_phy_dma_addr;
	int sizeof_txdesc_space;

	void *rxdesc_space;
	struct pcnet32_rx_head	*RxDescArray;           /* Index of 256-alignment Rx Descriptor buffer */
	IOBufferMemoryDescriptor *rx_descMd;
	IOPhysicalAddress rxdesc_phy_dma_addr;
	int sizeof_rxdesc_space;	
	
	bool PCNetInitBoard();
	bool PCNetProbeAndStartBoard();
	bool PCNetStopBoard();
	
	bool increaseActivationLevel(UInt32 level);
	bool decreaseActivationLevel(UInt32 level);
	bool setActivationLevel(UInt32 level);
	
	bool PCNetHwStart();
			
	bool AllocateDescriptorsMemory();
	bool PCNetInitRing();
	bool PCNetResetRing();
	void FreeDescriptorsMemory();
	
	bool PCNetInitEventSources(IOService *provider);
	bool PCNetOpenAdapter();
	void PCNetCloseAdapter();
	void PCNetTxClear();
	void PCNetRestart(unsigned int csr0_bits);
	
	
    void PCNetInterrupt(OSObject * client, IOInterruptEventSource * src, int count);
	void PCNetRxInterrupt();
	void PCNetTxInterrupt();
	void PCNetTxTimeout(OSObject *owner, IOTimerEventSource * timer);
	
	bool PCNetGetLink();
	
	bool OSAddNetworkMedium(UInt32 type, UInt32 bps, UInt32 index);
/*	
	u16 pcnet32_wio_read_csr (unsigned long addr, int index);
	void pcnet32_wio_write_csr (unsigned long addr, int index, u16 val);
	u16 pcnet32_wio_read_bcr (unsigned long addr, int index);
	void pcnet32_wio_write_bcr (unsigned long addr, int index, u16 val);
	u16 pcnet32_wio_read_rap (unsigned long addr);
	void pcnet32_wio_write_rap (unsigned long addr, u16 val);
	void pcnet32_wio_reset (unsigned long addr);
	int pcnet32_wio_check (unsigned long addr);
	
	u16 pcnet32_dwio_read_csr (unsigned long addr, int index);
	void pcnet32_dwio_write_csr (unsigned long addr, int index, u16 val);
	u16 pcnet32_dwio_read_bcr (unsigned long addr, int index);
	void pcnet32_dwio_write_bcr (unsigned long addr, int index, u16 val);
	u16 pcnet32_dwio_read_rap (unsigned long addr);
	void pcnet32_dwio_write_rap (unsigned long addr, u16 val);
	void pcnet32_dwio_reset (unsigned long addr);
	int pcnet32_dwio_check (unsigned long addr);	
*/
	
};

#endif //_PCNet_H_
