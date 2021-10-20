package transport

import (
	// "errors"
	"flag"
	"fmt"
	"sync"
	// "os"
	// "reflect"
	// "strings"

	flowmessage "github.com/cloudflare/goflow/v3/pb"
	"github.com/cloudflare/goflow/v3/utils"

	"database/sql"
	"github.com/ClickHouse/clickhouse-go"
	// proto "github.com/golang/protobuf/proto"
)



var (
	ClickHouseAddr *string
	ClickHousePort *int
	ClickHouseUser *string
	ClickHousePassword *string
	ClickHouseDatabase *string
	count uint64
	tx *sql.Tx

	dbConn *sql.DB
)

type ClickHouseState struct {
	FixedLengthProto bool
}




func RegisterFlags() {
	ClickHouseAddr   = flag.String("ch.addr", "127.0.0.1", "ClickHouse DB Host")
	ClickHousePort   = flag.Int("ch.port", 9000, "ClickHouse DB port")
	ClickHouseUser   = flag.String("ch.username", "default", "ClickHouse username")
	ClickHousePassword   = flag.String("ch.password", "default", "ClickHouse password")
	ClickHouseDatabase   = flag.String("ch.database", "default", "ClickHouse database")

	// future: add batch size to batch insert
}


func StartClickHouseConnection(logger utils.Logger) (*ClickHouseState, error) {
		
	count = 0

	if ClickHouseAddr == nil {
        temp := "<nil>" // *string cannot be initialized
        ClickHouseAddr = &temp // in one statement
    }

	fmt.Printf("clickhouse server on %v:%v\n", *ClickHouseAddr, *ClickHousePort)

	connStr := fmt.Sprintf("tcp://%s:%d?username=%s&password=%s&database=%s&debug=true",
		 *ClickHouseAddr, *ClickHousePort, *ClickHouseUser, *ClickHousePassword, *ClickHouseDatabase)


	// open DB dbConnion stuff
	connect, err := sql.Open("clickhouse", connStr)
	dbConn = connect
	if err != nil {
		logger.Fatalf("couldn't dbConn to db (%v)", err)
	}
	if err := dbConn.Ping(); err != nil {
		if exception, ok := err.(*clickhouse.Exception); ok {
			fmt.Printf("[%d] %s \n%s\n", exception.Code, exception.Message, exception.StackTrace)
		} else {
			fmt.Println(err)
		}
		// return
	}

	// create DB schema, if not exist 
	_, err = dbConn.Exec(fmt.Sprintf`
		CREATE DATABASE IF NOT EXISTS %s
	`,  *ClickHouseDatabase))
	if err != nil {
		logger.Fatalf("couldn't create database '%s' (%v)", *ClickHouseDatabase, err)
	}

	// use MergeTree engine to optimize storage
	//https://clickhouse.tech/docs/en/engines/table-engines/mergetree-family/mergetree/
	_, err = dbConn.Exec(fmt.Sprintf(`
	CREATE TABLE IF NOT EXISTS %s.nflow (
    
	    TimeReceived UInt32,
	    TimeFlowStart UInt32,
	    TimeFlowEnd UInt32,
	    Bytes UInt16,
	    Etype UInt32,
	    Packets UInt64,
	    SrcAddr UInt32,
	    DstAddr UInt32,
	    SrcPort UInt32,
	    DstPort UInt32,
	    Proto UInt32,
	    SrcMac UInt64,
	    DstMac UInt64,
	    SrcVlan UInt32,
	    DstVlan UInt32,
	    VlanId UInt32,
	    FlowType UInt8

	) ENGINE = MergeTree() 
	ORDER BY (TimeReceived, SrcAddr, SrcPort, DstAddr, DstPort)
	PARTITION BY DstAddr
	SAMPLE BY SrcAddr
	`,  *ClickHouseDatabase))

	if err != nil {
		logger.Fatalf("couldn't create table (%v)", err)
	}


	// start transaction prep

	

	// defer stmt.Close()
	state := ClickHouseState { FixedLengthProto: true }

	return &state, nil

	
}

func ipv4BytesToUint32(b []byte) (uint32) {
	return uint32(b[0]) << 24 + uint32(b[1]) << 16 + uint32(b[2]) << 8 + uint32(b[3])
}

func ClickHouseInsert(fm *flowmessage.FlowMessage, stmt *sql.Stmt, wg *sync.WaitGroup) {
	// extract fields out of the flow message
	
	

	// assume and encode as IPv4 (even if its v6)
	srcAddr := ipv4BytesToUint32(fm.GetSrcAddr()[:4])
	dstAddr := ipv4BytesToUint32(fm.GetDstAddr()[:4])
	

	count += 1
	// fmt.Printf("stmt: %v\n", stmt)
	if _, err := stmt.Exec(
		fm.GetTimeReceived(),
		fm.GetTimeFlowStart(),
		fm.GetTimeFlowEnd(),
		fm.GetBytes(),
		fm.GetEtype(),
		fm.GetPackets(),
		srcAddr,
		dstAddr,
		fm.GetSrcPort(),
		fm.GetDstPort(),
		fm.GetProto(),
		fm.GetSrcMac(),
		fm.GetDstMac(),
		fm.GetSrcVlan(),
		fm.GetDstVlan(),
		fm.GetVlanId(),
		uint8(fm.GetType()),
	); err != nil {
		fmt.Printf("error inserting record (%v)\n", err)
	}

	wg.Done()
	
	// -----------------------------------------------

	fmt.Printf("src (%v) %v:%v\ndst (%v) %v:%v\ncount:%v\n------\n",
	 	srcAddr,
	 	fm.GetSrcAddr(), 
		fm.GetSrcPort(), 
		dstAddr,
		fm.GetDstAddr(), 
		fm.GetDstPort(),
		count)



}

func (s ClickHouseState) Publish(msgs []*flowmessage.FlowMessage) {
	// ht: this is all you need to implement for the transport interface
	// needs to be async??

	// we need a semaphore / counter that increments inside the goroutines
	// WaitGroup ~= semaphore
	
	var wg sync.WaitGroup

	tx, _  = dbConn.Begin()

	stmt, err := tx.Prepare(fmt.Sprintf(`INSERT INTO %s.nflow(TimeReceived, 
		TimeFlowStart,TimeFlowEnd,Bytes,Etype,Packets,SrcAddr,DstAddr,SrcPort,
		DstPort,Proto,SrcMac,DstMac,SrcVlan,DstVlan,VlanId,FlowType) 
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, *ClickHouseDatabase))

	if (err != nil) {
		fmt.Printf("Couldn't prepare statement (%v)\n", err)
		// stmt.Close()
		return
	}


	for _, msg := range msgs {
		wg.Add(1)
		go ClickHouseInsert(msg, stmt, &wg)
	}

	wg.Wait()
	defer stmt.Close()

	if err := tx.Commit(); err != nil {
		fmt.Printf("Couldn't commit transactions (%v)\n", err)
	}



	
	// commit after all of those are inserted 
	// fmt.Println("\noutside loop!\n")

}
