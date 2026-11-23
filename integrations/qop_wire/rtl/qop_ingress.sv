module qop_ingress(input wire clk,rst_n,input wire valid,input wire [7:0] data,output reg ready,output reg frame_valid,output reg [2047:0] frame,output reg reject);
reg [7:0] pos;reg [2047:0] bufreg;
always @(posedge clk) begin
 if(!rst_n)begin pos<=0;bufreg<=0;frame<=0;frame_valid<=0;reject<=0;ready<=1;end
 else begin frame_valid<=0;reject<=0;
 if(valid && ready)begin bufreg[pos*8+:8]<=data;
 if(pos==255)begin pos<=0;
 if(bufreg[63:0]==64'h003130765f506f51 && bufreg[191:128]<=bufreg[255:192] && bufreg[287:256]>=1 && bufreg[287:256]<=3 && bufreg[319:288]==0)begin frame<={data,bufreg[2039:0]};frame_valid<=1;end else reject<=1;
 end else pos<=pos+1'b1;
 end end end
endmodule
