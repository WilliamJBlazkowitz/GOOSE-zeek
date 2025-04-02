@load base/packet-protocols/ethernet

module GOOSE;

export {
    # Append the value LOG to the Log::ID enumerable.
    redef enum Log::ID += { LOG };

    # Define a new type called GOOSE::goose_packet.
    type goose_packet: record {
        date: time &log;
        inter: interval &log &optional;
        length: count &log &optional;
        macadress: string &log &optional;
        MaxTime: count &log &optional;
        confRev: count &log &optional;
        appid: count &log &optional;
        lengthHeader: count &log &optional;
        reserved1: count &log &optional;
        reserved2: count &log &optional;
        lengthPdu: count &log &optional;
        timeAllowedtoLive: count &log &optional;
        goID: string &log &optional;
        stNum: count &log &optional;
        sqNum: count &log &optional;
        numDatSetEntries: count &log &optional;
        description: string &log;
    };
  # Define a new record to store informations about transfert mechanism
  type transfert: record {
    stNum: count;
    sqNum: count;
    timestamp: time;
    inter: interval &optional;
  };
}

global Previous: table[string] of transfert = table();

# this event execute the script when Zeek is executed.
event zeek_init() &priority=10
  {
    # if the Ethernet frame has 0x88b8 for tag Zeek transfert the parsing task to spicy::GOOSE
    if ( ! PacketAnalyzer::try_register_packet_analyzer_by_name("Ethernet", 0x88b8, "spicy::GOOSE") )
            Reporter::error("cannot register Spicy analyzer");

    # if the VLAN frame has 0x88b8 for tag Zeek transfert the parsing task to spicy::GOOSE
    if ( ! PacketAnalyzer::try_register_packet_analyzer_by_name("VLAN", 0x88b8, "spicy::GOOSE") )
            Reporter::error("cannot register Spicy analyzer");

    # Create the logging stream to goose.log
    Log::create_stream(LOG, [$columns=goose_packet, $path="goose"]);

    local path = getenv("PWD");
  }

# This event execute the script each time a goose frame is read.
event goose(appid: count, lengthHeader: count, reserved1: count, reserved2: count, tag: count, lengthPdu: count, gocbRef: string, timeAllowedtoLive: count,
   Dataset: string, goID: string, Time: count, st_Num: count, sq_Num: count, Test: bool, confRev: count, ndsCom: bool, numDatSetEntries: count, allData: vector of count) &priority=1
  {

    local p =  get_current_packet_header();

    # Check if the destination MAC address are within the range defined by the
    # standard
    if (p$l2$dst < "01:0c:cd:01:00:00" || p$l2$dst > "01:0c:cd:01:01:ff")
      {
        Log::write(GOOSE::LOG, [$date = network_time(), $macadress= p$l2$dst, $description="Destination MAC address out of range"]);
      }

    # Check if the frame size is inside the range defined by the standard
    if  (p$l2$len > 1527)
      {
        Log::write(GOOSE::LOG, [$date = network_time(), $length= p$l2$len, $description="GOOSE frame size is over 1527"]);
      }

    # Check if reserved1 and reserved2 fields are set to 0 considering that the IEDs
    # used haven't authentication or encryption mechanism
    if (reserved1 != 0 || reserved2 != 0)
      {
        Log::write(GOOSE::LOG, [$date = network_time(), $reserved1=reserved1, $reserved2=reserved2, $description="Value of fields reserved1 or reserved2 aren't at 0"]);
      }


    # Check if St_Num and Sq_Num fields are under the limit (4294967295)
    if (st_Num > 4294967295 || sq_Num > 4294967295)
      {
        Log::write(GOOSE::LOG, [$date = network_time(), $stNum= st_Num, $sqNum= sq_Num, $description="Value of fields st_Num or sq_Num over 4294967295"]);
      }

    # Check if the fields lengthHeader and lengthPdupdu are consistent
    if ((lengthPdu + 11) != lengthHeader)
      {
        Log::write(GOOSE::LOG, [$date = network_time(), $lengthHeader=lengthHeader, $lengthPdu=lengthPdu, $description="Values of fields lengthHeader and lengthPdu are unconsistent"]);
      }

    # Check if numDatSetEntries is consistent with allData
    if (numDatSetEntries != |allData|)
      {
        Log::write(GOOSE::LOG, [$date = network_time(), $numDatSetEntries=numDatSetEntries, $description="Values of fields numDatSetEntries and the number of data are different"]);
      }
# This part check if goose communication mechanism is compliant with the IEC 61850

    if (goID in Previous)
      {
        if (st_Num == Previous[goID]$stNum)
          {
            local inter = network_time() - Previous[goID]$timestamp;

            # Check if the sequence number is consistent with the previous frame
            if (sq_Num != Previous[goID]$sqNum + 1)
              {
                Log::write(GOOSE::LOG, [$date = network_time(), $sqNum=sq_Num, $goID=goID, $description=fmt("Value of field sqNum is unconsistent it should be equal to %d", Previous[goID]$sqNum + 1)]);
              }
            # Check if the time interval is consistent with the previous frame
         }

        else if (st_Num == Previous[goID]$stNum + 1)
          {

            # Check if the sequence number is correctly set to 0
            if (sq_Num != 0)
            {
              Log::write(GOOSE::LOG, [$date = network_time(), $inter=inter, $description="Unconsistent time interval with the previous frame"]);
            }
          }

        # Check if the sequence number and the state number is consistent with the previous frame
        else
          {
            Log::write(GOOSE::LOG, [$date = network_time(), $stNum=sq_Num, $goID=goID, $description="Value of field stNum is unconsistent"]);
          }
      Previous[goID]$stNum = st_Num;
      Previous[goID]$sqNum = sq_Num;
      Previous[goID]$timestamp = network_time();
      Previous[goID]$inter = inter;
    }
  }
