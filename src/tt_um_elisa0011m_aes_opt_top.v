/*
tt_um_elisa0011m_aes_top.v - AES-128 (TinyTapeout, three-module architecture)

    Submodules used:
        sbox_rom      : clocked 256-byte S-box (1-cycle latency)
        shift_rows    : combinational byte permutation
        mix_columns   : combinational column mixing

    Key schedule: inlined as combinational Verilog function (sbox_func + rcon)

    FSM states:
        S_IDLE  : wait for start, apply initial AddRoundKey on start
        S_SBOX  : present ShiftRows(state) to sbox_rom, wait one cycle
        S_ROUND : read sbox output, apply MixColumns + AddRoundKey,
                  advance key schedule

    Timing:
        Cycle 0     : start=1, state <= pt ^ RK0
        Cycle 1     : S_SBOX (round 1)  — sbox_rom latches
        Cycle 2     : S_ROUND (round 1) — MixColumns + RK1
        ...
        Cycle 19    : S_SBOX (round 10) — sbox_rom latches
        Cycle 20    : S_ROUND (round 10) — no MixColumns, done=1

    Total latency: 21 cycles after start

    Serial protocol (unchanged):
        1. load_key=1 for 16 cycles, data_in = key bytes MSB-first
        2. load_pt=1  for 16 cycles, data_in = plaintext bytes MSB-first
        3. start=1 for one cycle
        4. wait for done=1, read ciphertext via data_out + out_shift

    Pin mapping (unchanged):
        ui_in[7:0]  = data_in
        uio_in[0]   = load_key
        uio_in[1]   = load_pt
        uio_in[2]   = start
        uio_in[3]   = out_shift
        uio_out[4]  = busy
        uio_out[5]  = done
        uo_out[7:0] = data_out

    Andrea Lee Mei Jin      34367047
    Elisa Naily Mohd Yazid  33590745
*/
`timescale 1ns/1ps
`default_nettype none

module tt_um_elisa0011m_aes_opt_top (
    input  wire [7:0] ui_in,
    output wire [7:0] uo_out,
    input  wire [7:0] uio_in,
    output wire [7:0] uio_out,
    output wire [7:0] uio_oe,
    input  wire       ena,
    input  wire       clk,
    input  wire       rst_n
);

    // ----------------------------------------------------------------
    // Pin mapping
    // ----------------------------------------------------------------

    wire [7:0] data_in   = ui_in;
    wire       load_key  = uio_in[0];
    wire       load_pt   = uio_in[1];
    wire       start     = uio_in[2];
    wire       out_shift = uio_in[3];

    reg        busy_r, done_r;
    reg [7:0]  data_out_r;

    assign uo_out  = data_out_r;
    assign uio_out = {2'b00, done_r, busy_r, 4'b0000};
    assign uio_oe  = 8'hF0;


    // ----------------------------------------------------------------
    // Serial input shift registers (unchanged)
    // ----------------------------------------------------------------

    reg [127:0] key_reg;
    reg [127:0] pt_reg;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            key_reg <= 128'b0;
            pt_reg  <= 128'b0;
        end else begin
            if (load_key) key_reg <= {key_reg[119:0], data_in};
            if (load_pt)  pt_reg  <= {pt_reg[119:0],  data_in};
        end
    end


    // ----------------------------------------------------------------
    // Combinational S-box for key schedule
    // (sbox_rom is clocked so cannot be used in combinational key schedule)
    // ----------------------------------------------------------------

    function [7:0] sbox_func;
        input [7:0] in;
        case (in)
            8'h00:sbox_func=8'h63; 8'h01:sbox_func=8'h7c; 8'h02:sbox_func=8'h77; 8'h03:sbox_func=8'h7b;
            8'h04:sbox_func=8'hf2; 8'h05:sbox_func=8'h6b; 8'h06:sbox_func=8'h6f; 8'h07:sbox_func=8'hc5;
            8'h08:sbox_func=8'h30; 8'h09:sbox_func=8'h01; 8'h0a:sbox_func=8'h67; 8'h0b:sbox_func=8'h2b;
            8'h0c:sbox_func=8'hfe; 8'h0d:sbox_func=8'hd7; 8'h0e:sbox_func=8'hab; 8'h0f:sbox_func=8'h76;
            8'h10:sbox_func=8'hca; 8'h11:sbox_func=8'h82; 8'h12:sbox_func=8'hc9; 8'h13:sbox_func=8'h7d;
            8'h14:sbox_func=8'hfa; 8'h15:sbox_func=8'h59; 8'h16:sbox_func=8'h47; 8'h17:sbox_func=8'hf0;
            8'h18:sbox_func=8'had; 8'h19:sbox_func=8'hd4; 8'h1a:sbox_func=8'ha2; 8'h1b:sbox_func=8'haf;
            8'h1c:sbox_func=8'h9c; 8'h1d:sbox_func=8'ha4; 8'h1e:sbox_func=8'h72; 8'h1f:sbox_func=8'hc0;
            8'h20:sbox_func=8'hb7; 8'h21:sbox_func=8'hfd; 8'h22:sbox_func=8'h93; 8'h23:sbox_func=8'h26;
            8'h24:sbox_func=8'h36; 8'h25:sbox_func=8'h3f; 8'h26:sbox_func=8'hf7; 8'h27:sbox_func=8'hcc;
            8'h28:sbox_func=8'h34; 8'h29:sbox_func=8'ha5; 8'h2a:sbox_func=8'he5; 8'h2b:sbox_func=8'hf1;
            8'h2c:sbox_func=8'h71; 8'h2d:sbox_func=8'hd8; 8'h2e:sbox_func=8'h31; 8'h2f:sbox_func=8'h15;
            8'h30:sbox_func=8'h04; 8'h31:sbox_func=8'hc7; 8'h32:sbox_func=8'h23; 8'h33:sbox_func=8'hc3;
            8'h34:sbox_func=8'h18; 8'h35:sbox_func=8'h96; 8'h36:sbox_func=8'h05; 8'h37:sbox_func=8'h9a;
            8'h38:sbox_func=8'h07; 8'h39:sbox_func=8'h12; 8'h3a:sbox_func=8'h80; 8'h3b:sbox_func=8'he2;
            8'h3c:sbox_func=8'heb; 8'h3d:sbox_func=8'h27; 8'h3e:sbox_func=8'hb2; 8'h3f:sbox_func=8'h75;
            8'h40:sbox_func=8'h09; 8'h41:sbox_func=8'h83; 8'h42:sbox_func=8'h2c; 8'h43:sbox_func=8'h1a;
            8'h44:sbox_func=8'h1b; 8'h45:sbox_func=8'h6e; 8'h46:sbox_func=8'h5a; 8'h47:sbox_func=8'ha0;
            8'h48:sbox_func=8'h52; 8'h49:sbox_func=8'h3b; 8'h4a:sbox_func=8'hd6; 8'h4b:sbox_func=8'hb3;
            8'h4c:sbox_func=8'h29; 8'h4d:sbox_func=8'he3; 8'h4e:sbox_func=8'h2f; 8'h4f:sbox_func=8'h84;
            8'h50:sbox_func=8'h53; 8'h51:sbox_func=8'hd1; 8'h52:sbox_func=8'h00; 8'h53:sbox_func=8'hed;
            8'h54:sbox_func=8'h20; 8'h55:sbox_func=8'hfc; 8'h56:sbox_func=8'hb1; 8'h57:sbox_func=8'h5b;
            8'h58:sbox_func=8'h6a; 8'h59:sbox_func=8'hcb; 8'h5a:sbox_func=8'hbe; 8'h5b:sbox_func=8'h39;
            8'h5c:sbox_func=8'h4a; 8'h5d:sbox_func=8'h4c; 8'h5e:sbox_func=8'h58; 8'h5f:sbox_func=8'hcf;
            8'h60:sbox_func=8'hd0; 8'h61:sbox_func=8'hef; 8'h62:sbox_func=8'haa; 8'h63:sbox_func=8'hfb;
            8'h64:sbox_func=8'h43; 8'h65:sbox_func=8'h4d; 8'h66:sbox_func=8'h33; 8'h67:sbox_func=8'h85;
            8'h68:sbox_func=8'h45; 8'h69:sbox_func=8'hf9; 8'h6a:sbox_func=8'h02; 8'h6b:sbox_func=8'h7f;
            8'h6c:sbox_func=8'h50; 8'h6d:sbox_func=8'h3c; 8'h6e:sbox_func=8'h9f; 8'h6f:sbox_func=8'ha8;
            8'h70:sbox_func=8'h51; 8'h71:sbox_func=8'ha3; 8'h72:sbox_func=8'h40; 8'h73:sbox_func=8'h8f;
            8'h74:sbox_func=8'h92; 8'h75:sbox_func=8'h9d; 8'h76:sbox_func=8'h38; 8'h77:sbox_func=8'hf5;
            8'h78:sbox_func=8'hbc; 8'h79:sbox_func=8'hb6; 8'h7a:sbox_func=8'hda; 8'h7b:sbox_func=8'h21;
            8'h7c:sbox_func=8'h10; 8'h7d:sbox_func=8'hff; 8'h7e:sbox_func=8'hf3; 8'h7f:sbox_func=8'hd2;
            8'h80:sbox_func=8'hcd; 8'h81:sbox_func=8'h0c; 8'h82:sbox_func=8'h13; 8'h83:sbox_func=8'hec;
            8'h84:sbox_func=8'h5f; 8'h85:sbox_func=8'h97; 8'h86:sbox_func=8'h44; 8'h87:sbox_func=8'h17;
            8'h88:sbox_func=8'hc4; 8'h89:sbox_func=8'ha7; 8'h8a:sbox_func=8'h7e; 8'h8b:sbox_func=8'h3d;
            8'h8c:sbox_func=8'h64; 8'h8d:sbox_func=8'h5d; 8'h8e:sbox_func=8'h19; 8'h8f:sbox_func=8'h73;
            8'h90:sbox_func=8'h60; 8'h91:sbox_func=8'h81; 8'h92:sbox_func=8'h4f; 8'h93:sbox_func=8'hdc;
            8'h94:sbox_func=8'h22; 8'h95:sbox_func=8'h2a; 8'h96:sbox_func=8'h90; 8'h97:sbox_func=8'h88;
            8'h98:sbox_func=8'h46; 8'h99:sbox_func=8'hee; 8'h9a:sbox_func=8'hb8; 8'h9b:sbox_func=8'h14;
            8'h9c:sbox_func=8'hde; 8'h9d:sbox_func=8'h5e; 8'h9e:sbox_func=8'h0b; 8'h9f:sbox_func=8'hdb;
            8'ha0:sbox_func=8'he0; 8'ha1:sbox_func=8'h32; 8'ha2:sbox_func=8'h3a; 8'ha3:sbox_func=8'h0a;
            8'ha4:sbox_func=8'h49; 8'ha5:sbox_func=8'h06; 8'ha6:sbox_func=8'h24; 8'ha7:sbox_func=8'h5c;
            8'ha8:sbox_func=8'hc2; 8'ha9:sbox_func=8'hd3; 8'haa:sbox_func=8'hac; 8'hab:sbox_func=8'h62;
            8'hac:sbox_func=8'h91; 8'had:sbox_func=8'h95; 8'hae:sbox_func=8'he4; 8'haf:sbox_func=8'h79;
            8'hb0:sbox_func=8'he7; 8'hb1:sbox_func=8'hc8; 8'hb2:sbox_func=8'h37; 8'hb3:sbox_func=8'h6d;
            8'hb4:sbox_func=8'h8d; 8'hb5:sbox_func=8'hd5; 8'hb6:sbox_func=8'h4e; 8'hb7:sbox_func=8'ha9;
            8'hb8:sbox_func=8'h6c; 8'hb9:sbox_func=8'h56; 8'hba:sbox_func=8'hf4; 8'hbb:sbox_func=8'hea;
            8'hbc:sbox_func=8'h65; 8'hbd:sbox_func=8'h7a; 8'hbe:sbox_func=8'hae; 8'hbf:sbox_func=8'h08;
            8'hc0:sbox_func=8'hba; 8'hc1:sbox_func=8'h78; 8'hc2:sbox_func=8'h25; 8'hc3:sbox_func=8'h2e;
            8'hc4:sbox_func=8'h1c; 8'hc5:sbox_func=8'ha6; 8'hc6:sbox_func=8'hb4; 8'hc7:sbox_func=8'hc6;
            8'hc8:sbox_func=8'he8; 8'hc9:sbox_func=8'hdd; 8'hca:sbox_func=8'h74; 8'hcb:sbox_func=8'h1f;
            8'hcc:sbox_func=8'h4b; 8'hcd:sbox_func=8'hbd; 8'hce:sbox_func=8'h8b; 8'hcf:sbox_func=8'h8a;
            8'hd0:sbox_func=8'h70; 8'hd1:sbox_func=8'h3e; 8'hd2:sbox_func=8'hb5; 8'hd3:sbox_func=8'h66;
            8'hd4:sbox_func=8'h48; 8'hd5:sbox_func=8'h03; 8'hd6:sbox_func=8'hf6; 8'hd7:sbox_func=8'h0e;
            8'hd8:sbox_func=8'h61; 8'hd9:sbox_func=8'h35; 8'hda:sbox_func=8'h57; 8'hdb:sbox_func=8'hb9;
            8'hdc:sbox_func=8'h86; 8'hdd:sbox_func=8'hc1; 8'hde:sbox_func=8'h1d; 8'hdf:sbox_func=8'h9e;
            8'he0:sbox_func=8'he1; 8'he1:sbox_func=8'hf8; 8'he2:sbox_func=8'h98; 8'he3:sbox_func=8'h11;
            8'he4:sbox_func=8'h69; 8'he5:sbox_func=8'hd9; 8'he6:sbox_func=8'h8e; 8'he7:sbox_func=8'h94;
            8'he8:sbox_func=8'h9b; 8'he9:sbox_func=8'h1e; 8'hea:sbox_func=8'h87; 8'heb:sbox_func=8'he9;
            8'hec:sbox_func=8'hce; 8'hed:sbox_func=8'h55; 8'hee:sbox_func=8'h28; 8'hef:sbox_func=8'hdf;
            8'hf0:sbox_func=8'h8c; 8'hf1:sbox_func=8'ha1; 8'hf2:sbox_func=8'h89; 8'hf3:sbox_func=8'h0d;
            8'hf4:sbox_func=8'hbf; 8'hf5:sbox_func=8'he6; 8'hf6:sbox_func=8'h42; 8'hf7:sbox_func=8'h68;
            8'hf8:sbox_func=8'h41; 8'hf9:sbox_func=8'h99; 8'hfa:sbox_func=8'h2d; 8'hfb:sbox_func=8'h0f;
            8'hfc:sbox_func=8'hb0; 8'hfd:sbox_func=8'h54; 8'hfe:sbox_func=8'hbb; 8'hff:sbox_func=8'h16;
            default: sbox_func = 8'h00;
        endcase
    endfunction


    // ----------------------------------------------------------------
    // Inline key schedule functions
    // ----------------------------------------------------------------

    function [31:0] rcon_func;
        input [3:0] round;
        case (round)
            4'd1:  rcon_func = 32'h01000000;
            4'd2:  rcon_func = 32'h02000000;
            4'd3:  rcon_func = 32'h04000000;
            4'd4:  rcon_func = 32'h08000000;
            4'd5:  rcon_func = 32'h10000000;
            4'd6:  rcon_func = 32'h20000000;
            4'd7:  rcon_func = 32'h40000000;
            4'd8:  rcon_func = 32'h80000000;
            4'd9:  rcon_func = 32'h1b000000;
            4'd10: rcon_func = 32'h36000000;
            default: rcon_func = 32'h00000000;
        endcase
    endfunction

    function [127:0] next_round_key_func;
        input [127:0] current_key;
        input [3:0]   round;
        reg [31:0] w0, w1, w2, w3;
        reg [31:0] rot, subrot, t0, t1, t2, t3;
        begin
            w0 = current_key[127:96];
            w1 = current_key[95:64];
            w2 = current_key[63:32];
            w3 = current_key[31:0];
            rot    = {w3[23:0], w3[31:24]};   // RotWord
            subrot = {sbox_func(rot[31:24]),   // SubWord
                      sbox_func(rot[23:16]),
                      sbox_func(rot[15:8]),
                      sbox_func(rot[7:0])};
            t0 = w0 ^ subrot ^ rcon_func(round);
            t1 = w1 ^ t0;
            t2 = w2 ^ t1;
            t3 = w3 ^ t2;
            next_round_key_func = {t0, t1, t2, t3};
        end
    endfunction


    // ----------------------------------------------------------------
    // ShiftRows — combinational, feeds sbox_rom inputs
    // ----------------------------------------------------------------

    reg  [127:0] state;
    wire [127:0] sr_out;

    shift_rows sr_inst (
        .state_in  (state),
        .state_out (sr_out)
    );


    // ----------------------------------------------------------------
    // 16x sbox_rom — clocked, 1-cycle latency
    // Input: sr_out (ShiftRows output)
    // Output: subbytes_out (SubBytes result, valid one cycle later)
    // ----------------------------------------------------------------

    wire [127:0] subbytes_out;
    genvar b;
    generate
        for (b = 0; b < 16; b = b + 1) begin : sb_gen
            wire [7:0] sb_byte;
            sbox_rom sb_inst (
                .clk     (clk),
                .addr_in (sr_out[127 - b*8 -: 8]),
                .data_out(sb_byte)
            );
            assign subbytes_out[127 - b*8 -: 8] = sb_byte;
        end
    endgenerate


    // ----------------------------------------------------------------
    // MixColumns — combinational, applied to sbox output in S_ROUND
    // ----------------------------------------------------------------

    wire [127:0] mc_out;
    mix_columns mc_inst (
        .state_in  (subbytes_out),
        .state_out (mc_out)
    );


    // ----------------------------------------------------------------
    // FSM
    // ----------------------------------------------------------------

    localparam [1:0]
        S_IDLE  = 2'd0,
        S_SBOX  = 2'd1,
        S_ROUND = 2'd2;

    reg [1:0]   state_fsm;
    reg [3:0]   round_num;
    reg [127:0] current_round_key;

    // Combinational next key — valid whenever current_round_key and round_num are stable
    wire [127:0] next_key = next_round_key_func(current_round_key, round_num);

    always @(posedge clk) begin
        if (!rst_n) begin
            state_fsm         <= S_IDLE;
            busy_r            <= 1'b0;
            done_r            <= 1'b0;
            state             <= 128'b0;
            round_num         <= 4'd0;
            current_round_key <= 128'b0;

        end else begin
            done_r <= 1'b0;  // default deassert

            case (state_fsm)

                S_IDLE: begin
                    busy_r <= 1'b0;
                    if (start) begin
                        state             <= pt_reg ^ key_reg;  // AddRoundKey RK0
                        current_round_key <= key_reg;           // seed for RK1
                        round_num         <= 4'd1;
                        busy_r            <= 1'b1;
                        state_fsm         <= S_SBOX;
                    end
                end

                S_SBOX: begin
                    // sr_out = ShiftRows(state) is already presented to sbox_rom inputs
                    // combinationally. The sbox_rom latches on this clock edge and will
                    // output the result (subbytes_out) on the next cycle in S_ROUND.
                    state_fsm <= S_ROUND;
                end

                S_ROUND: begin
                    // subbytes_out = SubBytes(ShiftRows(prev_state)) is now valid
                    current_round_key <= next_key;

                    if (round_num == 4'd10) begin
                        // Final round: SubBytes + ShiftRows + AddRoundKey (no MixColumns)
                        state     <= subbytes_out ^ next_key;
                        done_r    <= 1'b1;
                        busy_r    <= 1'b0;
                        state_fsm <= S_IDLE;
                    end else begin
                        // Rounds 1-9: SubBytes + ShiftRows + MixColumns + AddRoundKey
                        state     <= mc_out ^ next_key;
                        round_num <= round_num + 4'd1;
                        state_fsm <= S_SBOX;
                    end
                end

                default: state_fsm <= S_IDLE;

            endcase
        end
    end


    // ----------------------------------------------------------------
    // Serial ciphertext output
    //
    // Timing: done_r fires on clk N. By clk N+1, state holds the
    // ciphertext (non-blocking update landed after clk N). The output
    // block reads done_r=1 at clk N+1 and correctly reads state.
    // ----------------------------------------------------------------

    reg [3:0] out_idx;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            out_idx    <= 4'd0;
            data_out_r <= 8'b0;
        end else begin
            if (done_r) begin
                out_idx    <= 4'd1;
                data_out_r <= state[127:120];
            end else if (out_shift) begin
                out_idx    <= out_idx + 4'd1;
                data_out_r <= (state >> (120 - 8*out_idx)) & 8'hFF;
            end
        end
    end


endmodule