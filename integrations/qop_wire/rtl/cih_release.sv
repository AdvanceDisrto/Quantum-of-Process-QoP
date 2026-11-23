module cih_release(input wire clk,rst_n,request,abort,ack_valid,ack_ok,input wire [255:0] digest,ack_digest,input wire [63:0] epoch,ack_epoch,output reg release_pulse,output reg pending);
reg [255:0] held;reg [63:0] ep,last_epoch;reg seen;reg [7:0] timer;
always @(posedge clk)begin
if(!rst_n)begin pending<=0;release_pulse<=0;held<=0;ep<=0;last_epoch<=0;seen<=0;timer<=0;end
else begin release_pulse<=0;
if(abort)pending<=0;
else if(pending)begin if(timer==8'hff)pending<=0;else if(ack_valid)begin pending<=0;if(ack_ok&&ack_digest==held&&ack_epoch==ep)begin release_pulse<=1;last_epoch<=ep;seen<=1;end end else timer<=timer+1'b1;end
else if(request&&(!seen||epoch>last_epoch))begin held<=digest;ep<=epoch;timer<=0;pending<=1;end end end
endmodule
