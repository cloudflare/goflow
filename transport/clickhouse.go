package transport

import (
	// "errors"

	"fmt"
	"net"
	"sync"

	// "os"
	// "reflect"
	// "strings"

	. "github.com/cloudflare/goflow/v3/conf"
	flowmessage "github.com/cloudflare/goflow/v3/pb"
	"github.com/cloudflare/goflow/v3/utils"

	"database/sql"

	"github.com/ClickHouse/clickhouse-go"
	// proto "github.com/golang/protobuf/proto"
)

var (
	count uint64
	tx    *sql.Tx

	dbConn *sql.DB
)

type ClickHouseState struct {
	FixedLengthProto bool
}

func StartClickHouseConnection(logger utils.Logger) (*ClickHouseState, error) {

	count = 0
	chDebug := "debug=false"

	if ClickHouseAddr == nil {
		temp := "<nil>"        // *string cannot be initialized
		ClickHouseAddr = &temp // in one statement
	}

	if *LogLevel == "debug" {
		chDebug = "debug=true"
	}

	connStr := fmt.Sprintf("tcp://%s:%d?username=%s&password=%s&database=%s&table=%s&%s",
		*ClickHouseAddr, *ClickHousePort, *ClickHouseUser, *ClickHousePassword, *ClickHouseDatabase, *ClickHouseTable, chDebug)

	// open DB dbConnion stuff
	connect, err := sql.Open("clickhouse", connStr)
	dbConn = connect
	if err != nil {
		logger.Fatalf("couldn't dbConn to db (%v)", err)
	} else {
		fmt.Printf("NetFlow-clickhouse collector\nConnected to clickhouse\n server on %v:%v\n database:%s\n table: %s \n debug: %s",
			*ClickHouseAddr, *ClickHousePort, *ClickHouseDatabase, *ClickHouseTable, chDebug)
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
	_, err = dbConn.Exec(fmt.Sprintf(`
		CREATE DATABASE IF NOT EXISTS %s
	`, *ClickHouseDatabase))
	if err != nil {
		logger.Fatalf("couldn't create database '%s' (%v)", *ClickHouseDatabase, err)
	}

	// use MergeTree engine to optimize storage
	//https://clickhouse.tech/docs/en/engines/table-engines/mergetree-family/mergetree/
	_, err = dbConn.Exec(fmt.Sprintf(`
	CREATE TABLE IF NOT EXISTS %s.%s (
    TimeReceived DateTime CODEC(Delta, ZSTD),
    TimeFlowStart DateTime CODEC(Delta, ZSTD),
    TimeFlowEnd DateTime CODEC(Delta, ZSTD),
    Bytes UInt64 CODEC(ZSTD(1)),
    Etype UInt32,
    Packets UInt32,
    SrcAddr IPv4 CODEC(ZSTD),
    DstAddr IPv4 CODEC(ZSTD),
    SrcPort UInt32,
    DstPort UInt32,
    Proto UInt32,
    SrcMac UInt64 CODEC(ZSTD),
    DstMac UInt64 CODEC(ZSTD),
    SrcVlan UInt32,
    DstVlan UInt32,
    VlanId UInt32,
    FlowType UInt8

) ENGINE = MergeTree()
ORDER BY (TimeReceived, SrcAddr, SrcPort, DstAddr, DstPort)
TTL TimeReceived + interval 18 week
PARTITION BY toYYYYMMDD(TimeReceived)
	`, *ClickHouseDatabase, *ClickHouseTable))

	if err != nil {
		logger.Fatalf("couldn't create table (%v)", err)
	}

	// start transaction prep

	// defer stmt.Close()
	state := ClickHouseState{FixedLengthProto: true}

	return &state, nil

}

func ipv4BytesToUint32(b []byte) uint32 {
	return uint32(b[0])<<24 + uint32(b[1])<<16 + uint32(b[2])<<8 + uint32(b[3])
}

func ClickHouseInsert(fm *flowmessage.FlowMessage, stmt *sql.Stmt, wg *sync.WaitGroup) {
	// extract fields out of the flow message

	// assume and encode as IPv4 (even if its v6)
	//srcAddr := ipv4BytesToUint32(fm.GetSrcAddr()[:4])
	//dstAddr := ipv4BytesToUint32(fm.GetDstAddr()[:4])
	srcAddr := net.IP(fm.GetSrcAddr()[:4]).To4().String()
	dstAddr := net.IP(fm.GetDstAddr()[:4]).To4().String()

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

	if *LogLevel == "debug" {
		fmt.Printf("src (%v) %v:%v\ndst (%v) %v:%v\nbytes:%v\ncount:%v\n------\n",
			srcAddr,
			fm.GetSrcAddr(),
			fm.GetSrcPort(),
			dstAddr,
			fm.GetDstAddr(),
			fm.GetDstPort(),
			fm.GetBytes(),
			count)
	}

}

func (s ClickHouseState) Publish(msgs []*flowmessage.FlowMessage) {
	// ht: this is all you need to implement for the transport interface
	// needs to be async??

	// we need a semaphore / counter that increments inside the goroutines
	// WaitGroup ~= semaphore

	var wg sync.WaitGroup

	tx, _ = dbConn.Begin()

	stmt, err := tx.Prepare(fmt.Sprintf(`INSERT INTO %s.%s(TimeReceived, 
		TimeFlowStart,TimeFlowEnd,Bytes,Etype,Packets,SrcAddr,DstAddr,SrcPort,
		DstPort,Proto,SrcMac,DstMac,SrcVlan,DstVlan,VlanId,FlowType) 
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, *ClickHouseDatabase, *ClickHouseTable))

	if err != nil {
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
