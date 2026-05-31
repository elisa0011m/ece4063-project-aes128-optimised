/*

mix_columns.v - AES-128 MixColumns transformation
	
	State column layout (MSB first):
		col 0 = state[127:96]
		col 1 = state[95:64]
		col 2 = state[63:32]
		col 3 = state[31:0]
		
	Andrea Lee Mei Jin 		34367047
	Elisa Naily Mohd Yazid 	33590745
	
*/

// Single column (from project brief)
module mixcolumns_one_column (
	input wire [31:0] col_in,
	output wire [31:0] col_out
);
	
	wire [7:0] s0, s1, s2, s3;
	wire [7:0] m0, m1, m2, m3;
	
	assign s0 = col_in[31:24];
	assign s1 = col_in[23:16];
	assign s2 = col_in[15:8];
	assign s3 = col_in[7:0];
	
	assign m0 = xtime(s0) ^ (xtime(s1) ^ s1) ^ s2 ^ s3;
	assign m1 = s0 ^ xtime(s1) ^ (xtime(s2) ^ s2) ^ s3;
	assign m2 = s0 ^ s1 ^ xtime(s2) ^ (xtime(s3) ^ s3);
	assign m3 = (xtime(s0) ^ s0) ^ s1 ^ s2 ^ xtime(s3);
	
	assign col_out = {m0, m1, m2, m3};
	
	function [7:0] xtime;
		input [7:0] b;
		begin
			if (b[7] == 1'b1)
				xtime = (b << 1) ^ 8'h1b;
			else
				xtime = (b << 1);
			end
	endfunction
	
	
endmodule
	
	
// Full MixColumns for all four columns
module mix_columns (
	input wire [127:0] state_in,
	output wire [127:0] state_out
);

	genvar i;
	generate
		for (i = 0; i < 4; i = i + 1) begin: mc_loop
			mixcolumns_one_column mc_inst (
				.col_in (state_in[127 - i*32 -: 32]),
				.col_out (state_out[127 - i*32 -: 32])
			);
		end
	endgenerate
	
	
endmodule