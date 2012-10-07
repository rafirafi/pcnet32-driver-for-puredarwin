

/* 
 * This driver is based on the pcnet32 Linux Driver from kernel 2.6.0
 * Use kcompat.h from osx86drivers.sourceforge.net
 * Use general structure from R1000.kext port by PSYSTAR, 2008.
 * 
 * Only support "PCnet/PCI II 79C970A".
 * 
 *	Copyright 2012 rafirafi
 * 
 */
 
/*
 * Original headers :
 *  
 * pcnet32.c: An AMD PCnet32 ethernet driver for linux. 
 *
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

#include "PCNet.h"

#define super IOEthernetController

#define RELEASE(x) do { if(x) { (x)->release(); (x) = 0; } } while(0)

OSDefineMetaClassAndStructors(PCNet, IOEthernetController)

int PCNet::max_interrupt_work = 80;

/**********************************************************************/

static u16 pcnet32_wio_read_csr (unsigned long addr, int index)
{
    OUTW (index, addr+PCNET32_WIO_RAP);
    return INW (addr+PCNET32_WIO_RDP);
}

static void pcnet32_wio_write_csr (unsigned long addr, int index, u16 val)
{
    OUTW (index, addr+PCNET32_WIO_RAP);
    OUTW (val, addr+PCNET32_WIO_RDP);
}

static u16 pcnet32_wio_read_bcr (unsigned long addr, int index)
{
    OUTW (index, addr+PCNET32_WIO_RAP);
    return INW (addr+PCNET32_WIO_BDP);
}

static void pcnet32_wio_write_bcr (unsigned long addr, int index, u16 val)
{
    OUTW (index, addr+PCNET32_WIO_RAP);
    OUTW (val, addr+PCNET32_WIO_BDP);
}

static u16 pcnet32_wio_read_rap (unsigned long addr)
{
    return INW (addr+PCNET32_WIO_RAP);
}

static void pcnet32_wio_write_rap (unsigned long addr, u16 val)
{
    OUTW (val, addr+PCNET32_WIO_RAP);
}

static void pcnet32_wio_reset (unsigned long addr)
{
    INW (addr+PCNET32_WIO_RESET);
}

static int pcnet32_wio_check (unsigned long addr)
{
    OUTW (88, addr+PCNET32_WIO_RAP);
    return (INW (addr+PCNET32_WIO_RAP) == 88);
}

/**********************************************************************/

static u16 pcnet32_dwio_read_csr (unsigned long addr, int index)
{
    OUTL (index, addr+PCNET32_DWIO_RAP);
    return (INL (addr+PCNET32_DWIO_RDP) & 0xffff);
}

static void pcnet32_dwio_write_csr (unsigned long addr, int index, u16 val)
{
    OUTL (index, addr+PCNET32_DWIO_RAP);
    OUTL (val, addr+PCNET32_DWIO_RDP);
}

static u16 pcnet32_dwio_read_bcr (unsigned long addr, int index)
{
    OUTL (index, addr+PCNET32_DWIO_RAP);
    return (INL (addr+PCNET32_DWIO_BDP) & 0xffff);
}

static void pcnet32_dwio_write_bcr (unsigned long addr, int index, u16 val)
{
    OUTL (index, addr+PCNET32_DWIO_RAP);
    OUTL (val, addr+PCNET32_DWIO_BDP);
}

static u16 pcnet32_dwio_read_rap (unsigned long addr)
{
    return (INL (addr+PCNET32_DWIO_RAP) & 0xffff);
}

static void pcnet32_dwio_write_rap (unsigned long addr, u16 val)
{
    OUTL (val, addr+PCNET32_DWIO_RAP);
}

static void pcnet32_dwio_reset (unsigned long addr)
{
    INL (addr+PCNET32_DWIO_RESET);
}

static int pcnet32_dwio_check (unsigned long addr)
{
    OUTL (88, addr+PCNET32_DWIO_RAP);
    return ((INL (addr+PCNET32_DWIO_RAP) & 0xffff) == 88);
}


/**********************************************************************/

static struct pcnet32_access pcnet32_wio = {
pcnet32_wio_read_csr,
pcnet32_wio_write_csr,
pcnet32_wio_read_bcr,
pcnet32_wio_write_bcr,
pcnet32_wio_read_rap,
pcnet32_wio_write_rap,
pcnet32_wio_reset
};

static struct pcnet32_access pcnet32_dwio = {
pcnet32_dwio_read_csr,
pcnet32_dwio_write_csr,
pcnet32_dwio_read_bcr,
pcnet32_dwio_write_bcr,
pcnet32_dwio_read_rap,
pcnet32_dwio_write_rap,
pcnet32_dwio_reset
};

/*
 * Initialization of driver instance,
 * i.e. resources allocation and so on.
*/
bool PCNet::init(OSDictionary *properties)
{
	DLog("PCNet::init(OSDictionary *properties)\n");
	if (super::init(properties) == false) return false;
	
	pciDev = NULL;
	workLoop = NULL;
	intSource = NULL;
    timerSource = NULL;
    netStats = NULL;
    etherStats = NULL;
	transmitQueue = NULL;
    netif = NULL;
	enabled = false;
	isInitialized = false;
	enabledForKDP = enabledForBSD = false;
	
    simpleLock = IOSimpleLockAlloc();
	
	return true;
}

/*
 * Calling before destroing driver instance.
 * Frees all allocated resources.
*/
void PCNet::free()
{
	DLog("PCNet::free()");
	
	//free resource of base instance
	if (intSource && workLoop)
	{
		//Detaching interrupt source from work loop
		workLoop->removeEventSource(intSource);
	}
  
	RELEASE(netif);
    RELEASE(intSource);
    RELEASE(timerSource);
    RELEASE(pciDev);
    RELEASE(workLoop);
    
	IOSimpleLockFree(simpleLock);
	
	FreeDescriptorsMemory();
	
	super::free();
} 

/*
 * Starting driver.
*/
bool PCNet::start(IOService *provider)
{
	bool success = false;
	DLog("::start(IOService *%08x)\n",  provider);
	
	do
	{
		pciDev = OSDynamicCast(IOPCIDevice, provider);
		if (!pciDev)
		{
			DLog("::start: Failed to cast provider\n");
			break;
		}
		if (super::start(pciDev) == false)
		{
			DLog("::start: Failed super::start returned false\n");
			break;
		}
		pciDev->retain();	
		
		if(pciDev->open(this) == false)
		{
			DLog("::start: Failed to open PCI Device/Nub\n");
			break;
		}
		
		//Adding Mac OS X PHY's
		mediumDict = OSDictionary::withCapacity(MEDIUM_INDEX_COUNT + 1);
		OSAddNetworkMedium(kIOMediumEthernetAuto, 0, MEDIUM_INDEX_AUTO);	
		OSAddNetworkMedium(kIOMediumEthernet10BaseT | kIOMediumOptionHalfDuplex, 10 * MBit, MEDIUM_INDEX_10HD);
		OSAddNetworkMedium(kIOMediumEthernet10BaseT | kIOMediumOptionFullDuplex, 10 * MBit, MEDIUM_INDEX_10FD);
		
		if (!publishMediumDictionary(mediumDict))
		{
			DLog("::start: Failed publishMediumDictionary returned false");
			break;
		}
		
		if (!PCNetProbeAndStartBoard())
		{
			DLog("::start: Failed PCNetProbeAndStartBoard returned false");
			break;
		}
		
		if (!AllocateDescriptorsMemory())
		{
			DLog("::start: Failed AllocateDescriptorsMemory returned false");
			break;
		}	
		
		if (!PCNetInitRing())
		{
			DLog("::start: Failed AllocateDescriptorsMemory returned false");
			break;
		}	
				
		if (!PCNetInitEventSources(provider))
		{
			DLog("::start: Failed PCNetInitEventSources returned false");
			break;
		}
		
		success = true;
	}
	while ( false );
		
	// Close our provider, it will be re-opened on demand when
	// our enable() is called by a client.
	if(pciDev)
	{
		pciDev->close(this);
	}
	
	do
	{
		// break if we've had an error before this
	    if ( false == success )
		{
			break;
		}
		//Attaching dynamic link layer
		if (false == attachInterface((IONetworkInterface**)&netif, false))
		{
			DLog("::start: Failed 'attachInterface' in attaching to data link layer\n");
			break;
		}

		netif->registerService();
		success = true;
	}
	while ( false );
	
	// set isInitialized status
	isInitialized = true;
	
	DLog("::start: returning '%d'\n",success);
	return success;
}

/*
 * Stopping driver.
*/
void PCNet::stop(IOService *provider)
{
	DLog("PCNet::stop(IOService *provider)\n");
	detachInterface(netif);
	PCNetStopBoard();
	super::stop(provider);
}

/**********************************************************************/

bool PCNet::OSAddNetworkMedium(UInt32 type, UInt32 bps, UInt32 index)
{
	IONetworkMedium *medium;
	
	medium = IONetworkMedium::medium( type, bps, 0, index );
	if (!medium) 
	{
		DLog("Couldn't allocate medium\n");		
		return false;
	}
	if (!IONetworkMedium::addMedium(mediumDict, medium)) 
	{
		DLog("Couldn't add medium\n");
		return false;
	}
	mediumTable[index] = medium;
	return true;
}

/**********************************************************************/

bool PCNet::AllocateDescriptorsMemory()
{
	//Allocating descriptor memory
	IOByteCount len;
	
	sizeof_txdesc_space = TX_RING_SIZE * sizeof(pcnet32_tx_head) + 256;
	tx_descMd = IOBufferMemoryDescriptor::withOptions(kIOMemoryPhysicallyContiguous,
														sizeof_txdesc_space,
														PAGE_SIZE);
														
	if (!tx_descMd || tx_descMd->prepare() != kIOReturnSuccess)
	{
		DLog("Couldn't allocate physical memory for tx_desc\n");
		return false;
	}
	
	txdesc_space = tx_descMd->getBytesNoCopy();
	txdesc_phy_dma_addr = tx_descMd->getPhysicalSegment(0, &len);
	
	
	sizeof_rxdesc_space = RX_RING_SIZE * sizeof(pcnet32_rx_head) + 256;
	rx_descMd = IOBufferMemoryDescriptor::withOptions(kIOMemoryPhysicallyContiguous,
														sizeof_rxdesc_space,
														PAGE_SIZE);
	
	if (!rx_descMd || rx_descMd->prepare() != kIOReturnSuccess)
	{
		DLog("Couldn't allocate physical memory for rx_desc\n");
		return false;
	}
	
	rxdesc_space = rx_descMd->getBytesNoCopy();
	rxdesc_phy_dma_addr = rx_descMd->getPhysicalSegment(0, &len);

	TxDescArray = reinterpret_cast<pcnet32_tx_head *>(txdesc_space);
	RxDescArray = reinterpret_cast<pcnet32_rx_head *>(rxdesc_space);
	
	return true;

}

/**********************************************************************/

bool PCNet::PCNetResetRing()
{

    tx_full = 0;
    cur_rx = cur_tx = 0;
    dirty_rx = dirty_tx = 0;
    
	//Ring initialization
	for(int i = 0; i < RX_RING_SIZE; i++)
	{
		RxDescArray[i].buf_length = ( -PKT_BUF_SZ );		
		RxDescArray[i].status = 0x8000;
		RxDescArray[i].msg_length = 0x0;				
	}  
	
	for(int i = 0; i < TX_RING_SIZE; i++)
	{
			TxDescArray[i].base = 0;			
			TxDescArray[i].status = 0;
			TxDescArray[i].length = 0;
			TxDescArray[i].misc = 0;
	}
	
	return true;	 

}

/**********************************************************************/

bool PCNet::PCNetInitRing()
{
    int i;

    tx_full = 0;
    cur_rx = cur_tx = 0;
    dirty_rx = dirty_tx = 0;
		 
	//Ring initialization
	for(int i = 0; i < RX_RING_SIZE; i++)
	{
		
		Rx_dbuff[i] = 0;
		Rx_skbuff_Md[i] = IOBufferMemoryDescriptor::withOptions(kIOMemoryPhysicallyContiguous,
														PKT_BUF_SZ,
														PAGE_SIZE);
		if (!Rx_skbuff_Md[i] || Rx_skbuff_Md[i]->prepare() != kIOReturnSuccess)
		{
			DLog("Couldn't allocate physical memory for Rx_dbuff, step %d\n", i);
			return false;
		}
		Rx_dbuff[i] = static_cast<uchar *>(Rx_skbuff_Md[i]->getBytesNoCopy());
		if (!Rx_dbuff[i])
		{
			DLog("Pointer in NULL, step %d\n", i);
			return false;
		}		
		IOByteCount len;
		Rx_skbuff_Dma[i] = Rx_skbuff_Md[i]->getPhysicalSegment(0, &len);
		// note : need to initialize all fields !!! IOBufferMemoryDescriptor::withOptions don't initialize to zero		
		RxDescArray[i].base = Rx_skbuff_Dma[i];
		RxDescArray[i].buf_length = ( -PKT_BUF_SZ );
		RxDescArray[i].status = 0x8000;
		RxDescArray[i].msg_length = 0x0;			
				
	}  
        
    /* The Tx buffer address is filled in as needed, but we do need to clear
       the upper ownership bit. */
 	//Ring initialization
	for(int i = 0; i < TX_RING_SIZE; i++)
	{
		
		Tx_dbuff[i] = NULL;
		Tx_skbuff_Md[i] = IOBufferMemoryDescriptor::withOptions(kIOMemoryPhysicallyContiguous,
																PKT_BUF_SZ,
																PAGE_SIZE);
		if (!Tx_skbuff_Md[i] || Tx_skbuff_Md[i]->prepare() != kIOReturnSuccess)
		{
			DLog("Couldn't allocate physical memory for Tx_dbuff, step %d\n", i);
			return false;
		}
		Tx_dbuff[i] = static_cast<uchar *>(Tx_skbuff_Md[i]->getBytesNoCopy());
		if (!Tx_dbuff[i])
		{
			DLog("Pointer in NULL, step %d\n", i);
			return false;
		}
		IOByteCount len;
		// note : need to initialize all fields !!! IOBufferMemoryDescriptor::withOptions don't initialize to zero
		Tx_skbuff_Dma[i] = static_cast<IOPhysicalAddress>(Tx_skbuff_Md[i]->getPhysicalSegment(0, &len));
		TxDescArray[i].base = Tx_skbuff_Dma[i];// note this is set to 0 later...
		TxDescArray[i].status = 0;
		TxDescArray[i].length = 0;
		TxDescArray[i].misc = 0;

	}      

    init_block->tlen_rlen = le16_to_cpu(TX_RING_LEN_BITS | RX_RING_LEN_BITS);
    for (i = 0; i < 6; i++)
		init_block->phys_addr[i] = dev_addr[i];
    init_block->rx_ring = rxdesc_phy_dma_addr;
    init_block->tx_ring = txdesc_phy_dma_addr;
    
    return true;
}

/**********************************************************************/

bool PCNet::PCNetInitBoard()
{
	pciDev->setBusMasterEnable(true);
	pciDev->setIOEnable(true);
	
	vendorId = pciDev->configRead16(0);
	deviceId = pciDev->configRead16(2);
	pciDev->enablePCIPowerManagement();
	
	IOSleep(10);
	
	pioBase = pciDev->configRead16(kIOPCIConfigBaseAddress0) & 0xFFFC;
	DLog("pio base 0x%04x\n", pioBase);
						
    int chip_version;
    char *chipname;
    
    access = NULL;
	
    /* reset the chip */
    pcnet32_wio_reset(pioBase);

    /* NOTE: 16-bit check is first, otherwise some older PCnet chips fail */
    if (pcnet32_wio_read_csr(pioBase, 0) == 4 && pcnet32_wio_check(pioBase)) {
	access = &pcnet32_wio;
    } else {
	pcnet32_dwio_reset(pioBase);
	if (pcnet32_dwio_read_csr(pioBase, 0) == 4 && pcnet32_dwio_check(pioBase)) {
	   access = &pcnet32_dwio;
	} else
		return false;
    }	

    chip_version = access->read_csr(pioBase, 88) | (access->read_csr(pioBase,89) << 16);
	DLog( "  PCnet chip version is %#x.\n", chip_version);
    if ((chip_version & 0xfff) != 0x003)
	    return false;
    
    /* initialize variables */
    chip_version = (chip_version >> 12) & 0xffff;
    
    switch (chip_version) {
    case 0x2621:
	chipname = "PCnet/PCI II 79C970A"; /* PCI */
	//fdx = 1;
	break;
    default:
	DLog( "PCnet version %#x, no PCnet32 chip.\n", chip_version);
	return false;
    }
	
	name = chipname;
	
	return true;
}

/**********************************************************************/

bool PCNet::PCNetProbeAndStartBoard()
{
	if (!PCNetInitBoard()) return false;

    u8 promaddr[6];
	int i;

    /* In most chips, after a chip reset, the ethernet address is read from the
     * station address PROM at the base address and programmed into the
     * "Physical Address Registers" CSR12-14.
     * As a precautionary measure, we read the PROM values and complain if
     * they disagree with the CSRs.  Either way, we use the CSR values, and
     * double check that they are valid.
     */
    for (i = 0; i < 3; i++) {
	unsigned int val;
	val = access->read_csr(pioBase, i+12) & 0x0ffff;
	/* There may be endianness issues here. */
	dev_addr[2*i] = val & 0x0ff;
	dev_addr[2*i+1] = (val >> 8) & 0x0ff;
    }

    /* read PROM address and compare with CSR address */
    for (i = 0; i < 6; i++)
	promaddr[i] = INB(pioBase + i);
    
    if( memcmp( promaddr, dev_addr, 6)
	|| !is_valid_ether_addr(dev_addr) ) {
	if( is_valid_ether_addr(promaddr) ){
	    DLog(" warning: CSR address invalid  using instead PROM address \n");
	    memcpy(dev_addr, promaddr, 6);
	}
    }

    /* if the ethernet address is not valid, force to 00:00:00:00:00:00 */
    if( !is_valid_ether_addr(dev_addr) )
	memset(dev_addr, 0, sizeof(dev_addr));

    for (i = 0; i < 6; i++)
		DLog(" %2.2x", dev_addr[i] );

    /* pci_alloc_consistent returns page-aligned memory, so we do not have to check the alignment */
    init_block = (struct pcnet32_init_block *)IOMallocContiguous( sizeof(struct pcnet32_init_block), PAGE_SIZE, &phys_init_block); 
    if ( ! init_block) {
		DLog(" %s failed to allocate init block\n", __FUNCTION__);		
		return false;
	}  
    memset(init_block, 0, sizeof(struct pcnet32_init_block) );
    
    full_duplex = 1;
	options |= PCNET32_PORT_FD;
	
    init_block->mode = le16_to_cpu(0x0003);	/* Disable Rx and Tx. */
    init_block->tlen_rlen = le16_to_cpu(TX_RING_LEN_BITS | RX_RING_LEN_BITS); 
    for (i = 0; i < 6; i++)
	init_block->phys_addr[i] = dev_addr[i];
    init_block->filter[0] = 0x00000000;
    init_block->filter[1] = 0x00000000;
    init_block->rx_ring = rxdesc_phy_dma_addr;
    init_block->tx_ring = txdesc_phy_dma_addr;
    
    /* switch pcnet32 to 32bit mode */
    access->write_bcr (pioBase, 20, 2);

    access->write_csr (pioBase, 1, (phys_init_block & 0xffff));
    access->write_csr (pioBase, 2, (phys_init_block >> 16));

    return true;

}

/**********************************************************************/

bool PCNet::PCNetInitEventSources(IOService *provider)
{
	DLog("PCNet::PCNetInitEventSources()\n");
	
	IOWorkLoop *loop = getWorkLoop(); //Needed, cause may be called before WorkLoop creation
	//Sanity check
	if (!loop)
	{
		DLog("::PCNetInitEventSources: Could not getWorkLoop.\n");
		return false;
	}
	
	transmitQueue = getOutputQueue();
	
	if (!transmitQueue)
	{ 
		DLog("::PCNetInitEventSources: Could not getOutputQueue.\n");
		return false;
	}
	
	intSource = IOInterruptEventSource::interruptEventSource(this, 
							OSMemberFunctionCast(IOInterruptEventSource::Action, this, &PCNet::PCNetInterrupt),
								pciDev);
				
	//Adding interrupt to our workloop event sources
	if (!intSource || loop->addEventSource(intSource) != kIOReturnSuccess)
	{
		DLog("::PCNetInitEventSources: Could not get InterruptEventSource and/or addEventSource.\n");
		return false;
	}
	
	intSource->enable();
	
	//Registering watchdog (i.e. if timeout exceeds)
	timerSource = IOTimerEventSource::timerEventSource(this, 
					OSMemberFunctionCast(IOTimerEventSource::Action, this, &PCNet::PCNetTxTimeout));
					
	if (!timerSource || loop->addEventSource(timerSource) != kIOReturnSuccess)
	{
		DLog("::PCNetInitEventSources: Could not get timerEventSource and/or addEventSource.\n");
		return false;
	}
	
	return true;
}

/**********************************************************************/

bool PCNet::PCNetOpenAdapter()
{
	DLog("bool PCNet::PCNetOpenAdapter()\n");
	PCNetHwStart();
	return true;
}

/**********************************************************************/

bool PCNet::PCNetHwStart()
{
    UInt16 val;
    int i;

    /* Check for a valid station address */
    if( !is_valid_ether_addr(dev_addr) )
		return false;

    /* Reset the PCNET32 */
    access->reset (pioBase);

    /* switch pcnet32 to 32bit mode */
    access->write_bcr (pioBase, 20, 2);

	DLog( " pcnet32_open() tx/rx rings %#x/%#x init %#x.\n",
	       txdesc_phy_dma_addr,
	       rxdesc_phy_dma_addr,
	       phys_init_block);
    
    /* set/reset autoselect bit */
    val = access->read_bcr (pioBase, 2) & ~2;
    if (options & PCNET32_PORT_ASEL)
	val |= 2;
    access->write_bcr (pioBase, 2, val);
    
    /* handle full duplex setting */
    if (full_duplex) {
	val = access->read_bcr (pioBase, 9) & ~3;
	if (options & PCNET32_PORT_FD) {
	    val |= 1;
	    if (options == (PCNET32_PORT_FD | PCNET32_PORT_AUI))
		val |= 2;
	} else if (options & PCNET32_PORT_ASEL) {
	/* workaround of xSeries250, turn on for 79C975 only */
	    i = ((access->read_csr(pioBase, 88) | (access->read_csr(pioBase,89) << 16)) >> 12) & 0xffff;
	    if (i == 0x2627) val |= 3;
	}
	access->write_bcr (pioBase, 9, val);
    }
    
    /* set/reset GPSI bit in test register */
    val = access->read_csr (pioBase, 124) & ~0x10;
    if ((options & PCNET32_PORT_PORTSEL) == PCNET32_PORT_GPSI)
	val |= 0x10;
    access->write_csr (pioBase, 124, val);
    
	if (options & PCNET32_PORT_ASEL) {  /* enable auto negotiate, setup, disable fd */
		val = access->read_bcr(pioBase, 32) & ~0x98;
		val |= 0x20;
		access->write_bcr(pioBase, 32, val);
	}

   
    init_block->mode = le16_to_cpu((options & PCNET32_PORT_PORTSEL) << 7);
    init_block->filter[0] = 0x00000000;
    init_block->filter[1] = 0x00000000;
    //Done in ::start, could also be done here.
    //if ( PCNetInitRing() )
	//return false;
    
    /* Re-initialize the PCNET32, and start it when done. */
    access->write_csr (pioBase, 1, phys_init_block &0xffff);
    access->write_csr (pioBase, 2, phys_init_block >> 16);

    access->write_csr (pioBase, 4, 0x0915);
    access->write_csr (pioBase, 0, 0x0001);

    transmitQueue->start();
    
    i = 0;
    while (i++ < 100)
	if (access->read_csr (pioBase, 0) & 0x0100)
	    break;
    /* 
     * We used to clear the InitDone bit, 0x0100, here but Mark Stockton
     * reports that doing so triggers a bug in the '974.
     */
    access->write_csr (pioBase, 0, 0x0042);

	DLog( "%s: pcnet32 open after %d ticks, init block %#x csr0 %4.4x.\n",
	       name, i, phys_init_block,
	       access->read_csr(pioBase, 0));

	return true; //always success...
}

/**********************************************************************/

//Interrupt handler
void PCNet::PCNetInterrupt(OSObject * client, IOInterruptEventSource * src, int count)
{
	// dont process interrupts until we're ready
	if(!this->isInitialized)
	{
		//DLog("Ignoring interrupt, card not initilized yet.\n");
		return;
	}
	
	// dont process interrupts until we're enabled
	if(!this->enabled)
	{
		//DLog("Ignoring interrupt, card not enabled?\n");
		return;
	}
		
	u16 csr0,rap;
    int boguscnt =  max_interrupt_work;
    must_restart = 0;
        
    rap = access->read_rap(pioBase);
    while ((csr0 = access->read_csr (pioBase, 0)) & 0x8600 && --boguscnt >= 0) {
	/* Acknowledge all of the current interrupt sources ASAP. */
	access->write_csr (pioBase, 0, csr0 & ~0x004f);

	must_restart = 0;

	//DLog( "%s: interrupt  csr0=%#2.2x new csr=%#2.2x.\n",
	//	   name, csr0, access->read_csr (pioBase, 0));

	if (csr0 & 0x0400)		/* Rx interrupt */
	    PCNetRxInterrupt();

	if (csr0 & 0x0200)		/* Tx-done interrupt */
	    PCNetTxInterrupt();		
	
	if (csr0 & 0x0800) {
	    DLog( "%s: Bus master arbitration failure, status %4.4x.\n",
		   name, csr0);
	    /* unlike for the lance, there is no restart needed */
	}

	if (must_restart) {
	    /* stop the chip to clear the error condition, then restart */
	    access->write_csr (pioBase, 0, 0x0004);
	    PCNetRestart(0x0002);
	}
    }

    /* Clear any other interrupt, and set interrupt enable. */
    access->write_csr (pioBase, 0, 0x7940);
    access->write_rap (pioBase,rap);
    
	//DLog( "%s: exiting interrupt, csr0=%#4.4x.\n",
	//       name, access->read_csr (pioBase, 0));


    return;
}

/**********************************************************************/

void PCNet::PCNetRxInterrupt()
{
    int entry = cur_rx & RX_RING_MOD_MASK;

    /* If we own the next entry, it's a new packet. Send it up. */
    while ((short)(RxDescArray[entry].status) >= 0) {
	int status = (short)(RxDescArray[entry].status) >> 8;

	if (status != 0x03) {			/* There was an error. */
	    /* There is a tricky error noted by John Murphy,...*/
	    RxDescArray[entry].status &= le16_to_cpu(0x03ff);
	} else {
	    /* Malloc up new buffer, compatible with net-2e. */
	    short pkt_len = ((RxDescArray[entry].msg_length) & 0xfff)-4;
	    struct __mbuf *skb = NULL;
			
	    if(pkt_len < 60) {
			DLog ( "%s: Runt packet!\n",name);
	    } 
	    else 
	    {
					
		//skb = Rx_skbuff[entry];
		skb = allocatePacket(PKT_BUF_SZ);
		if (!skb) continue;
		
		memcpy(mbuf_data(skb), Rx_dbuff[entry], pkt_len);
		
		if (skb != NULL)
		{
			mbuf_setlen(skb, pkt_len);
			//TO-DO: Add network stack notification
			//DLog("Receive: packet len %d, mised packets %d\n", pkt_len, ReadMMIO32(RxMissed));
			netif->inputPacket(skb, pkt_len, IONetworkInterface::kInputOptionQueuePacket);
			netif->flushInputQueue();
		}
		else// (skb == NULL)
		{
			//DLog("Allocate n_skb failed!\n");
            int i;
		    DLog( "%s: Memory squeeze, deferring packet.\n", name);
		    for (i = 0; i < RX_RING_SIZE; i++)
			if ((short)(RxDescArray[(entry+i) & RX_RING_MOD_MASK].status) < 0)
			    break;

		    if (i > RX_RING_SIZE -2) {
			RxDescArray[entry].status |= 0x8000;
			cur_rx++;
		    }
		    break;			
		}			

		last_rx = jiffies;
	    }
	}
	/*
	 * The docs say that the buffer length isn't touched, but Andrew Boyd
	 * of QNX reports that some revs of the 79C965 clear it.
	 */
	RxDescArray[entry].buf_length = (-PKT_BUF_SZ);
	RxDescArray[entry].status |= (0x8000);
	entry = (++cur_rx) & RX_RING_MOD_MASK;
    }

}

/**********************************************************************/

//Tx done
void PCNet::PCNetTxInterrupt()
{	
		/* Tx-done interrupt */
	    unsigned int cur_dirty_tx = dirty_tx;

	    while (cur_dirty_tx < cur_tx) {
		int entry = cur_dirty_tx & TX_RING_MOD_MASK;
		int status = TxDescArray[entry].status;
			
		if (status < 0)
		    break;		/* It still hasn't been Txed */

		//mark buf as non allocated
		TxDescArray[entry].base = 0;

		if (status & 0x4000) {
		    /* There was an major error, log it. */
			DLog("%s: Tx FIFO error!\n", name);
			must_restart = 1;
		    }
		    

		/* We must free the original skb */
		if (Tx_skbuff[entry]) {
			freePacket(Tx_skbuff[entry]);
			Tx_skbuff[entry] = NULL;
		}
	
		cur_dirty_tx++;
	    }

	    if (cur_tx - cur_dirty_tx >= TX_RING_SIZE) {
		DLog("%s: out-of-sync dirty pointer, %d vs. %d, full=%d.\n",
			name, cur_dirty_tx, cur_tx, tx_full);
		cur_dirty_tx += TX_RING_SIZE;
	    }

	    if (tx_full &&
		cur_dirty_tx > cur_tx - TX_RING_SIZE + 2) {
		/* The ring is no longer full, clear tbusy. */
		tx_full = 0;
	    }
	    dirty_tx = cur_dirty_tx;

}

/**********************************************************************/

void PCNet::PCNetTxClear()
{
    int i;

    for (i = 0; i < TX_RING_SIZE; i++) {
		if (Tx_skbuff[i]) {
			freePacket(Tx_skbuff[i]);
		}
    }
}

/**********************************************************************/
/*
 *  TODO : implement really, for now just dump debug info
 */

void PCNet::PCNetTxTimeout(OSObject *owner, IOTimerEventSource * timer)
{
	  	
    // Transmitter timeout, serious problems.
	DLog("%s: transmit timed out, resetting.\n", __FUNCTION__);
	DDLog(" Ring data dump: dirty_tx %d cur_tx %d%s cur_rx %d.\n",
	   dirty_tx, cur_tx, tx_full ? " (full)" : "",
	   cur_rx);
	DDLog("Base   Buflen Msg_length Status  \n");
	DDLog("			RX =>  \n");
	for (int i = 0 ; i < RX_RING_SIZE; i++)
	DDLog(" %08x %04x %08x %04x\n",
	   RxDescArray[i].base, -RxDescArray[i].buf_length,
	   RxDescArray[i].msg_length, (unsigned)RxDescArray[i].status);
	DDLog("\n");
	DDLog(" 		TX =>  \n");	
	for (int i = 0 ; i < TX_RING_SIZE; i++)
	DDLog(" %08x %04x %08x %04x\n",
	   TxDescArray[i].base, -TxDescArray[i].length,
	   TxDescArray[i].misc, (unsigned)TxDescArray[i].status);
	DDLog("\n");

}

/**********************************************************************/

void PCNet::PCNetRestart(unsigned int csr0_bits)
{
    int i;
    
    DLog(" %s \n", __FUNCTION__);
    
    PCNetTxClear();
	//contrarly to linux we don't realloc, so just clear desc. fields  
    if ( PCNetResetRing() == false )
		return;
    
    /* ReInit Ring */
    access->write_csr (pioBase, 0, 1);
    i = 0;
    while (i++ < 1000)
	if (access->read_csr (pioBase, 0) & 0x0100)
	    break;

    access->write_csr (pioBase, 0, csr0_bits); 
}

/**********************************************************************/

UInt32 PCNet::outputPacket(mbuf_t m, void *param)
{

    u16 status;
    int entry;
  	IOInterruptState	intState;
	int buf_len;
	buf_len = mbuf_pkthdr_len(m);
	
	//DLog( "%s: pcnet32_start_xmit() called, csr0 %4.4x.\n",
	//       name, access->read_csr(pioBase, 0));
	

	intState = IOSimpleLockLockDisableInterrupt( simpleLock );
	
    /* Default status -- will not enable Successful-TxDone
     * interrupt when that option is available to us.
     */
    status = 0x8300;	
  
    /* Fill in a Tx ring entry */
  
    /* Mask to ring buffer boundary. */
    entry = cur_tx & TX_RING_MOD_MASK;
  
	Tx_skbuff[entry] = m;

	uchar *data_ptr = Tx_dbuff[entry];
		ulong pkt_snd_len = 0;
		mbuf_t cur_buf = m;
	
		do
		{
			if (mbuf_data(cur_buf))	
				memcpy(data_ptr, mbuf_data(cur_buf), mbuf_len(cur_buf));
			data_ptr += mbuf_len(cur_buf);
			pkt_snd_len += mbuf_len(cur_buf);
		}
		while(((cur_buf = mbuf_next(cur_buf)) != NULL) && ((pkt_snd_len + mbuf_len(cur_buf)) <= buf_len));
		buf_len = pkt_snd_len;
	
    /* Caution: the write order is important here, set the base address
	 with the "ownership" bits last. */
	
    TxDescArray[entry].length = ( - buf_len );
	
    TxDescArray[entry].misc = 0x00000000;
	
    TxDescArray[entry].base = Tx_skbuff_Dma[entry];// We need to mark the entry as allocated here !
    TxDescArray[entry].status = status;


    cur_tx++;

    /* Trigger an immediate send poll. */
    access->write_csr (pioBase, 0, 0x0048);

    trans_start = jiffies;

    if (TxDescArray[(entry+1) & TX_RING_MOD_MASK].base == 0) {
	//transmitQueue->start();
    } else {
	tx_full = 1;
	//transmitQueue->stop();
    }
    
	IOSimpleLockUnlockEnableInterrupt( simpleLock, intState);
	
	return kIOReturnOutputSuccess;
}
/**********************************************************************/

/*
 * Set or clear the promiscious for this adaptor.
 * TODO : not tested at all.
 */

IOReturn PCNet::setPromiscuousMode(bool enabled)
{
	IOInterruptState	intState;
 
	intState = IOSimpleLockLockDisableInterrupt( simpleLock );
	
	if (enabled) {	
	//Log any net taps.
	DLog( "%s: Promiscuous mode enabled.\n", name);
	init_block->mode = (0x8000 | (options & PCNET32_PORT_PORTSEL) << 7);
	
    //set all multicast bits
	init_block->filter[0] = 0xffffffff;
	init_block->filter[1] = 0xffffffff;

	
	}
	else
	{
	init_block->mode = ((options & PCNET32_PORT_PORTSEL) << 7);	 
	}
    
    access->write_csr (pioBase, 0, 0x0004); // Temporarily stop the lance.

    PCNetRestart(0x0042); //  Resume normal operation
    
	IOSimpleLockUnlockEnableInterrupt( simpleLock, intState);
	
	return kIOReturnSuccess;
	
}

/**********************************************************************/

/*
 * Set or clear the multicast filter for this adaptor.
 * TODO : not tested at all.
 */
IOReturn PCNet::setMulticastMode(bool enabled)
{

	IOInterruptState	intState;
 
	intState = IOSimpleLockLockDisableInterrupt( simpleLock );

	if (enabled) {
	DLog( "%s: Multicast mode enabled.\n", name);	
	init_block->mode = ((options & PCNET32_PORT_PORTSEL) << 7);
	//pcnet32_load_multicast ();
	}
	else
	{
		//not sure how to disable, so I clear the filter instead
		init_block->filter[0] = 0x00000000;
		init_block->filter[1] = 0x00000000;	
	}
    
    access->write_csr (pioBase, 0, 0x0004); // Temporarily stop the lance.

    PCNetRestart(0x0042); //  Resume normal operation
    
	IOSimpleLockUnlockEnableInterrupt( simpleLock, intState);
	
	return kIOReturnSuccess;
	
}

/**********************************************************************/

/*
 * TODO : not tested at all.
 */
 
/* taken from the sunlance driver, which it took from the depca driver */
IOReturn PCNet::setMulticastList(IOEthernetAddress *addrs, UInt32 count)
{
	
    volatile u16 *mcast_table = (u16 *)&init_block->filter;
        
    u32 crc;
	
    // set all multicast bits : PROMISCIOUS ?  filter overflow ?
				   
    //if (dev->flags & IFF_ALLMULTI){ 
	if ( count > 32)//!TO DO : CHECK THIS
	{//if count > max stockable count (32 ???) just accept every address
	init_block->filter[0] = 0xffffffff;
	init_block->filter[1] = 0xffffffff;
	return kIOReturnSuccess;
    }

					   
    // clear the multicast filter
    init_block->filter[0] = 0;//uint32_t
    init_block->filter[1] = 0;//uint32_t

    // Add addresses 
    for ( int i = 0; i < count; i++, addrs++){
	
	// multicast address?
	if ( !( *(reinterpret_cast<uchar *>(addrs)) & 0x1) )//not usre it's ok
	    continue;
	
	crc = ether_crc_le(6, reinterpret_cast<uchar *>(addrs));//6 = ETH_ALEN //ok in kcompat.h
	
	crc = crc >> 26;
	mcast_table [crc >> 4] = mcast_table [crc >> 4] | (1 << (crc & 0xf));
    }
    
    return kIOReturnSuccess;
}


/**********************************************************************/

bool PCNet::PCNetStopBoard()
{
	return true;
}

/**********************************************************************/

/*
 * TODO : implement this correctly
 */

void PCNet::PCNetCloseAdapter()
{


	DLog( "%s: Shutting down ethercard, status was %2.2x.\n",
	       name, access->read_csr (pioBase, 0));

    /* We stop the PCNET32 here -- it occasionally polls memory if we don't. */
    access->write_csr (pioBase, 0, 0x0004);

    /*
     * Switch back to 16bit mode to avoid problems with dumb 
     * DOS packet driver after a warm reboot
     */
    access->write_bcr (pioBase, 20, 4);
    
    return;
}

/**********************************************************************/

/*
 * Returns a string describing the vendor of the network controller. The caller is responsible for releasing the string object returned.
*/
const OSString *PCNet::newVendorString() const
{
	DLog("PCNet::newVendorString() const\n");
	return OSString::withCString("Amd");
}

/**********************************************************************/

/*
 * Returns a string describing the model of the network controller. The caller is responsible for releasing the string object returned.
*/
const OSString *PCNet::newModelString() const
{
	DLog("PCNet::newModelString() const\n");
	return OSString::withCString(name);
}

/**********************************************************************/

/*
 * Debugger polled-mode transmit handler.
 * This method must be implemented by a driver that supports kernel debugging.
 * pkt - pointer to a transmit buffer containing the packet to be sent on the network.
 * pktSize - the size of the transmit buffer in bytes.
*/
void PCNet::sendPacket(void * pkt, UInt32 pkt_len)
{
	DLog("PCNet::sendPacket(void * pkt, UInt32 pkt_len)\n");
}

/**********************************************************************/

/*
 * Debugger polled-mode receive handler.
 * This method must be implemented by a driver that supports kernel debugging.
 * pkt - address of a receive buffer where the received packet should be stored. This buffer has room for 1518 bytes.
 * pktSize - address where the number of bytes received must be recorded. Set this to zero if no packets were received during the timeout interval.
 * timeout - the maximum amount of time in milliseconds to poll for a packet to arrive before this method must return.
*/
void PCNet::receivePacket(void *pkt, UInt32 *pkt_len, UInt32 timeout)
{
	DLog("PCNet::receivePacket(void *pkt, UInt32 *pkt_len, UInt32 timeout)\n");
}

/**********************************************************************/

IOOutputQueue *PCNet::createOutputQueue()
{
	DLog("PCNet::createOutputQueue()\n");
	//Sharing one event source with transmith/receive handles
	return IOGatedOutputQueue::withTarget(this, getWorkLoop());
}

/**********************************************************************/

/*
 * Method called by IONetworkController prior to the initial getWorkLoop() call.
*/
bool PCNet::createWorkLoop()
{
	DLog("PCNet::createWorkLoop()\n");
	workLoop = IOWorkLoop::workLoop();
	if (workLoop) return true;
	else return false;
}

/**********************************************************************/

IOWorkLoop *PCNet::getWorkLoop() const
{
	DLog("PCNet::getWorkLoop()\n");
	return workLoop;
}

/**********************************************************************/

IOReturn PCNet::getHardwareAddress(IOEthernetAddress *addr)
{
		
	addr->bytes[0] = dev_addr[0];
    addr->bytes[1] = dev_addr[1];
    addr->bytes[2] = dev_addr[2];
    addr->bytes[3] = dev_addr[3];
    addr->bytes[4] = dev_addr[4];
    addr->bytes[5] = dev_addr[5];
	
	DLog( " %s MAC: MAC %x.%x.%x.%x.%x.%x \n", __FUNCTION__, addr->bytes[0],
		 addr->bytes[1],addr->bytes[2],addr->bytes[3],addr->bytes[4],addr->bytes[5] );
	
	return kIOReturnSuccess;
	
}

/**********************************************************************/

/*
 * Implements the framework for a generic network controller.
*/
IOReturn PCNet::registerWithPolicyMaker(IOService *policyMaker)
{
	DLog("PCNet::registerWithPolicyMaker(IOService *policyMaker)\n");
	
	//Grabed from ViaRhine
    enum 
	{
        kPowerStateOff = 0,
        kPowerStateOn,
        kPowerStateCount
    };

    static IOPMPowerState powerStateArray[ kPowerStateCount ] =
    {
        { 1,0,0,0,0,0,0,0,0,0,0,0 },
        { 1,IOPMDeviceUsable,IOPMPowerOn,IOPMPowerOn,0,0,0,0,0,0,0,0 }
    };

    IOReturn ret;

    ret = policyMaker->registerPowerDriver( this, powerStateArray,
                                            kPowerStateCount );
    
    return ret;
}

/**********************************************************************/

IOReturn PCNet::setPowerState(unsigned long powerStateOrdinal, IOService *policyMaker)
{
	DLog("PCNet::setPowerState(unsigned long powerStateOrdinal, IOService *policyMaker)\n");

    if ( 0 == powerStateOrdinal ) 
	{
     // Going to sleep. Perform state-saving tasks here.
	 DLog("going to sleep...\n");
	 this->setLinkStatus( kIONetworkLinkValid );
	}
	else
	{
     // Waking up. Perform device initialization here.
	 DLog("waking/wake up from sleep...\n");
     this->setLinkStatus( kIONetworkLinkValid | kIONetworkLinkActive );
    }

	//TO-DO: Add power state support (IOPMAckImplied)
	return IOPMAckImplied;
}

/**********************************************************************/

void PCNet::getPacketBufferConstraints(IOPacketBufferConstraints *constraints) const
{
	DLog("PCNet::getPacketBufferConstraints(IOPacketBufferConstraints *constraints) const\n");
	constraints->alignStart = kIOPacketBufferAlign16; // ? linux driver tells 16bytes align
	constraints->alignLength = kIOPacketBufferAlign1; // ? no restriction 
}

/**********************************************************************/

/*
 * A request from an interface client to enable the controller.
*/
IOReturn PCNet::enable(IONetworkInterface *netif)
{
	DLog("PCNet::enable(IONetworkInterface *netif)\n");
	
	if (enabledForBSD) return kIOReturnSuccess;
	
	enabledForBSD = setActivationLevel(kActivationLevelBSD);
	if (enabledForBSD)
	{
		this->enabled = true;
		return kIOReturnSuccess;
	}
	else return kIOReturnIOError;
}

/**********************************************************************/

/*
 * A request from an interface client to disable the controller.
*/
IOReturn PCNet::disable(IONetworkInterface *netif)
{
	enabledForBSD = false;
	
	setActivationLevel(enabledForKDP ? kActivationLevelKDP : kActivationLevelNone);
	
	this->enabled = false;
	return kIOReturnSuccess;
}

/**********************************************************************/

/*
 * Method only ok with PCNET32_79C970A
 * TODO: not tested at all
 */

bool PCNet::PCNetGetLink()
{
	bool r;
	IOInterruptState	intState;
  	
	intState = IOSimpleLockLockDisableInterrupt( simpleLock );
	
	//if (lp->chip_version >= PCNET32_79C970A)
		r = (access->read_bcr(pioBase, 4) != 0xc0);
	
	IOSimpleLockUnlockEnableInterrupt( simpleLock, intState);

	return r;
}

/**********************************************************************/

/*
 * A client request to change the medium selection.
 * This method is called when a client issues a command for the controller to change its 
 * current medium selection. The implementation must call setSelectedMedium() after the change 
 * has occurred. This method call is synchronized by the workloop's gate.
*/
IOReturn PCNet::selectMedium(const IONetworkMedium *medium)
{
	DLog("PCNet::selectMedium(const IONetworkMedium *medium)\n");
	DLog("index %d\n", medium->getIndex());
	

	if (medium) 
	{
	UInt16 val = val = access->read_bcr (pioBase, 32) & ~0x38;	
		
		switch (medium->getIndex())
		{
		case MEDIUM_INDEX_AUTO:
		case MEDIUM_INDEX_10HD:
			break;
		case MEDIUM_INDEX_10FD:
			val |= 0x10;
			break;
		}
		access->write_bcr(pioBase, 32, val);		
		setCurrentMedium(medium);
	}
	else
	{
		DLog("Selected medium is NULL\n");
	}
	
	if ( PCNetGetLink() )
	{	
		setLinkStatus(kIONetworkLinkActive | kIONetworkLinkValid, getSelectedMedium(), 10 * MBit, NULL);
	}
	else
	{	
		setLinkStatus(kIONetworkLinkValid, NULL, 0, NULL);
	}

	return kIOReturnSuccess;
}

/**********************************************************************/

bool PCNet::increaseActivationLevel(UInt32 level)
{
	bool ret = false;

	switch (level)
	{
	case kActivationLevelKDP:
		if (!pciDev) break;
		pciDev->open(this);
		
		// PHY medium selection.
		const IONetworkMedium *medium = getSelectedMedium();
		if (!medium)
		{
			DLog("Selected medium is NULL, forcing to autonegotiation\n");
			medium = mediumTable[MEDIUM_INDEX_AUTO];
		}
		else
		{
			DLog("Selected medium index %d", medium->getIndex());
		}
		
		selectMedium(medium);
		timerSource->setTimeoutMS(TX_TIMEOUT);
		ret = true;
		break;
	case kActivationLevelBSD:
		if (!PCNetOpenAdapter()) break;
		transmitQueue->setCapacity(kTransmitQueueCapacity);
		transmitQueue->start();
		
		ret = true;
		break;
	}
	
	return ret;
}

/**********************************************************************/

bool PCNet::decreaseActivationLevel(UInt32 level)
{
	switch (level)
	{
	case kActivationLevelKDP:
		timerSource->cancelTimeout();
		
		if (pciDev) pciDev->close(this);
		break;
	case kActivationLevelBSD:
		transmitQueue->stop();
	
		transmitQueue->setCapacity(0);
		transmitQueue->flush();
		PCNetCloseAdapter();
		break;
	}
	
	return true;
}

/**********************************************************************/

bool PCNet::setActivationLevel(UInt32 level)
{
    bool success = false;

	DLog("setActivationLevel %d\n", level);

    if (activationLevel == level) return true;

    for ( ; activationLevel > level; activationLevel--) 
    {
        if ((success = decreaseActivationLevel(activationLevel)) == false)
            break;
    }

    for ( ; activationLevel < level; activationLevel++ ) 
    {
        if ((success = increaseActivationLevel(activationLevel+1)) == false)
            break;
    }

    return success;
}

/**********************************************************************/

/*
 * Configures a newly created network interface object.
 * This method configures an interface object that was created by createInterface(). 
 * Subclasses can override this method to customize and examine the interface object that will be 
 * attached to the controller as a client.
*/

/*
 * TODO : should be possible to get linux stats here.
 */
 
bool PCNet::configureInterface(IONetworkInterface *netif)
{
	DLog("PCNet::configureInterface(IONetworkInterface *interface)\n");
	IONetworkData * data;

    if (!super::configureInterface(netif)) return false;
	
    // Get the generic network statistics structure.
    data = netif->getParameter( kIONetworkStatsKey );
    if ( !data || !(netStats = (IONetworkStats *) data->getBuffer()) ) 
    {
        return false;
    }

    // Get the Ethernet statistics structure.
    data = netif->getParameter( kIOEthernetStatsKey );
    if ( !data || !(etherStats = (IOEthernetStats *) data->getBuffer()) ) 
    {
        return false;
    }

    return true;
}

/**********************************************************************/

void PCNet::FreeDescriptorsMemory()
{
	PCNetTxClear();
	if (tx_descMd)
	{
		tx_descMd->complete();
		tx_descMd->release();
		tx_descMd = NULL;
	}
	
	if (rx_descMd)
	{
		rx_descMd->complete();
		rx_descMd->release();
		rx_descMd = NULL;
	}
	
	for(int i = 0; i < RX_RING_SIZE; i++)
	{
		if (Rx_skbuff_Md[i])
		{
			Rx_skbuff_Md[i]->complete();
			Rx_skbuff_Md[i]->release();
			Rx_skbuff_Md[i] = NULL;
		}
	}
	
	for(int i = 0; i < TX_RING_SIZE; i++)
	{
		if (Tx_skbuff_Md[i])
		{
			Tx_skbuff_Md[i]->complete();
			Tx_skbuff_Md[i]->release();
			Tx_skbuff_Md[i] = NULL;
		}
	}	
}

/**********************************************************************/
