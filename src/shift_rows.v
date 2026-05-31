/*

shift_rows.v - AES-128 ShiftRows transformation
	
	Convert the 128-bit state into a 4x4 byte matrix filled column-by-column:
		row 0 = state[127:120] state[95:88] state[63:56] state[31:24]
		row 1 = state[119:112] state[87:80] state[55:48] state[23:16]
		row 2 = state[111:104] state[79:72] state[47:40] state[15:8]
		row 3 = state[103:96]  state[71:64] state[39:32] state[7:0]
		
		
	Row i will be rotated left by i byte positions
	
	Andrea Lee Mei Jin 		34367047
	Elisa Naily Mohd Yazid 	33590745
	
*/

module shift_rows (
	input wire [127:0] state_in,
	output wire [127:0] state_out
);
	
	
	genvar r, c;
	
	// Extract bytes
	wire [7:0] b[0:3][0:3];	// b[r][c]
	generate
		for (r = 0; r < 4; r = r + 1) begin: row_loop
			for (c = 0; c < 4; c = c + 1) begin: col_loop
				assign b[r][c] = state_in[127 - (c*4 + r)*8 -: 8];
			end
		end
	endgenerate
	
	
	// Shift
	wire [7:0] s[0:3][0:3];
	generate
		for (r = 0; r < 4; r= r + 1) begin: srow_loop
			for (c = 0; c < 4; c = c + 1) begin: scol_loop
				assign s[r][c] = b[r][(c + r) % 4];
			end
		end
	endgenerate
	
	
	// Pack state back into flat bus
	generate
		for (r = 0; r < 4; r = r + 1) begin: prow_loop
			for (c = 0; c < 4; c = c + 1) begin: pcol_loop
				assign state_out[127 - (c*4 + r)*8 -: 8] = s[r][c];
			end
		end
	endgenerate
	

endmodule