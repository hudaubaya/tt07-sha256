/*
 * sha07_block: one SHA-256 compression on the tt07 round core.
 *
 *   h_out = h_in + compress(h_in, block)
 *
 * The core (tt_um_xeniarose_sha256, instantiated here) only performs a single
 * round per command, so this module supplies everything else: the message
 * schedule W[0..63] (a rolling 16-word window), the 64 round constants K,
 * loading A..H, reading them back and the final addition.
 *
 * Core access is on-chip, one operation per clock: io_clk is held high and
 * the address changes every cycle (the core acts on every clock edge with
 * io_clk high).  A compression takes 32 writes (A..H) + 64 x 9 (W, K, round
 * trigger) + 33 cycles of pipelined reads, about 645 cycles.
 *
 * Words are big-endian within the buses: h_in[255:224] is H0, block[511:480]
 * is message word 0 (bytes 0..3).
 *
 * h_out is valid only in the cycle done is high and zero otherwise.  After
 * every compression (and on abort) the schedule window, the working copy of
 * h_in and the readback are cleared and the core is reset for one cycle, so
 * nothing derived from the block remains.
 */

`default_nettype none

module sha07_block (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire         abort,
    input  wire [255:0] h_in,
    input  wire [511:0] block,
    output wire         busy,
    output reg          done,
    output reg  [255:0] h_out
);

  localparam S_IDLE  = 3'd0,
             S_LOADH = 3'd1,
             S_ROUND = 3'd2,
             S_READ  = 3'd3,
             S_ADD   = 3'd4;

  reg [2:0]   state;
  reg [5:0]   cnt;       // byte counter for load/read
  reg [5:0]   round;
  reg [3:0]   sub;       // 0..3 W bytes, 4..7 K bytes, 8 trigger
  reg [31:0]  w [0:15];  // schedule window: w[0] is W[round]
  reg [255:0] hreg;      // working copy of h_in
  reg [255:0] rd;        // A..H read back, shifted in byte by byte
  reg         scrub;     // core reset request (registered)

  // core pins
  reg  [7:0] ui;         // {io_clk, io_we(read), addr[5:0]}
  reg  [7:0] uio;
  wire [7:0] core_uo, core_uio_out, core_uio_oe;

  tt_um_xeniarose_sha256 core (
      .ui_in  (ui),
      .uo_out (core_uo),
      .uio_in (uio),
      .uio_out(core_uio_out),
      .uio_oe (core_uio_oe),
      .ena    (1'b1),
      .clk    (clk),
      .rst_n  (rst_n && !scrub)
  );

  assign busy = (state != S_IDLE);

  // ---- round constants -------------------------------------------------------
  function [31:0] k_of(input [5:0] t);
    case (t)
      6'd0:  k_of = 32'h428a2f98; 6'd1:  k_of = 32'h71374491;
      6'd2:  k_of = 32'hb5c0fbcf; 6'd3:  k_of = 32'he9b5dba5;
      6'd4:  k_of = 32'h3956c25b; 6'd5:  k_of = 32'h59f111f1;
      6'd6:  k_of = 32'h923f82a4; 6'd7:  k_of = 32'hab1c5ed5;
      6'd8:  k_of = 32'hd807aa98; 6'd9:  k_of = 32'h12835b01;
      6'd10: k_of = 32'h243185be; 6'd11: k_of = 32'h550c7dc3;
      6'd12: k_of = 32'h72be5d74; 6'd13: k_of = 32'h80deb1fe;
      6'd14: k_of = 32'h9bdc06a7; 6'd15: k_of = 32'hc19bf174;
      6'd16: k_of = 32'he49b69c1; 6'd17: k_of = 32'hefbe4786;
      6'd18: k_of = 32'h0fc19dc6; 6'd19: k_of = 32'h240ca1cc;
      6'd20: k_of = 32'h2de92c6f; 6'd21: k_of = 32'h4a7484aa;
      6'd22: k_of = 32'h5cb0a9dc; 6'd23: k_of = 32'h76f988da;
      6'd24: k_of = 32'h983e5152; 6'd25: k_of = 32'ha831c66d;
      6'd26: k_of = 32'hb00327c8; 6'd27: k_of = 32'hbf597fc7;
      6'd28: k_of = 32'hc6e00bf3; 6'd29: k_of = 32'hd5a79147;
      6'd30: k_of = 32'h06ca6351; 6'd31: k_of = 32'h14292967;
      6'd32: k_of = 32'h27b70a85; 6'd33: k_of = 32'h2e1b2138;
      6'd34: k_of = 32'h4d2c6dfc; 6'd35: k_of = 32'h53380d13;
      6'd36: k_of = 32'h650a7354; 6'd37: k_of = 32'h766a0abb;
      6'd38: k_of = 32'h81c2c92e; 6'd39: k_of = 32'h92722c85;
      6'd40: k_of = 32'ha2bfe8a1; 6'd41: k_of = 32'ha81a664b;
      6'd42: k_of = 32'hc24b8b70; 6'd43: k_of = 32'hc76c51a3;
      6'd44: k_of = 32'hd192e819; 6'd45: k_of = 32'hd6990624;
      6'd46: k_of = 32'hf40e3585; 6'd47: k_of = 32'h106aa070;
      6'd48: k_of = 32'h19a4c116; 6'd49: k_of = 32'h1e376c08;
      6'd50: k_of = 32'h2748774c; 6'd51: k_of = 32'h34b0bcb5;
      6'd52: k_of = 32'h391c0cb3; 6'd53: k_of = 32'h4ed8aa4a;
      6'd54: k_of = 32'h5b9cca4f; 6'd55: k_of = 32'h682e6ff3;
      6'd56: k_of = 32'h748f82ee; 6'd57: k_of = 32'h78a5636f;
      6'd58: k_of = 32'h84c87814; 6'd59: k_of = 32'h8cc70208;
      6'd60: k_of = 32'h90befffa; 6'd61: k_of = 32'ha4506ceb;
      6'd62: k_of = 32'hbef9a3f7; default: k_of = 32'hc67178f2;
    endcase
  endfunction

  // ---- message schedule --------------------------------------------------------
  function [31:0] rotr(input [31:0] x, input [4:0] n);
    rotr = (x >> n) | (x << (6'd32 - n));
  endfunction

  wire [31:0] sig0  = rotr(w[1], 5'd7) ^ rotr(w[1], 5'd18) ^ (w[1] >> 3);
  wire [31:0] sig1  = rotr(w[14], 5'd17) ^ rotr(w[14], 5'd19) ^ (w[14] >> 10);
  wire [31:0] w_new = sig1 + w[9] + sig0 + w[0];   // W[round + 16]
  wire [31:0] k_now = k_of(round);

  // byte b of register r in h_in order (H0 = A)
  wire [2:0]  ld_reg  = cnt[4:2];
  wire [1:0]  ld_byte = cnt[1:0];
  wire [31:0] ld_word = hreg[255 - 32*ld_reg -: 32];

  // A..H read back: byte i of the stream is register i/4, byte i%4 (LSB first)
  wire [255:0] rd_words;
  genvar g;
  generate
    for (g = 0; g < 32; g = g + 1) begin : g_rd
      // rd holds bytes in arrival order, first byte in the top bits
      assign rd_words[255 - 32*(g / 4) - 8*(3 - g % 4) -: 8] = rd[255 - 8*g -: 8];
    end
  endgenerate

  wire [255:0] sum;
  generate
    for (g = 0; g < 8; g = g + 1) begin : g_sum
      assign sum[255 - 32*g -: 32] = hreg[255 - 32*g -: 32] + rd_words[255 - 32*g -: 32];
    end
  endgenerate

  integer i;

  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      state <= S_IDLE;
      cnt   <= 6'd0;
      round <= 6'd0;
      sub   <= 4'd0;
      for (i = 0; i < 16; i = i + 1) w[i] <= 32'd0;
      hreg  <= 256'd0;
      rd    <= 256'd0;
      h_out <= 256'd0;
      done  <= 1'b0;
      scrub <= 1'b0;
      ui    <= 8'd0;
      uio   <= 8'd0;
    end else begin
      done  <= 1'b0;
      h_out <= 256'd0;
      scrub <= 1'b0;

      if (abort) begin
        state <= S_IDLE;
        for (i = 0; i < 16; i = i + 1) w[i] <= 32'd0;
        hreg  <= 256'd0;
        rd    <= 256'd0;
        scrub <= 1'b1;
        ui    <= 8'd0;
        uio   <= 8'd0;
      end else begin
        case (state)
          S_IDLE: begin
            ui  <= 8'd0;
            uio <= 8'd0;
            if (start) begin
              hreg <= h_in;
              for (i = 0; i < 16; i = i + 1) w[i] <= block[511 - 32*i -: 32];
              cnt   <= 6'd0;
              state <= S_LOADH;
            end
          end

          // write A..H, one byte per cycle (register r = cnt/4, byte cnt%4)
          S_LOADH: begin
            ui  <= {1'b1, 1'b0, 1'b0, ld_reg, ld_byte};  // addr = 4*reg + byte
            uio <= ld_word[8*ld_byte +: 8];
            if (cnt == 6'd31) begin
              round <= 6'd0;
              sub   <= 4'd0;
              state <= S_ROUND;
            end
            cnt <= cnt + 6'd1;
          end

          // per round: W bytes (addr 32..35), K bytes (36..39), trigger (63)
          S_ROUND: begin
            if (sub < 4'd4) begin
              ui  <= {2'b10, 4'd8, sub[1:0]};
              uio <= w[0][8*sub[1:0] +: 8];
            end else if (sub < 4'd8) begin
              ui  <= {2'b10, 4'd9, sub[1:0]};
              uio <= k_now[8*sub[1:0] +: 8];
            end else begin
              ui  <= {2'b10, 6'd63};
              uio <= 8'd0;
            end

            if (sub == 4'd8) begin
              for (i = 0; i < 15; i = i + 1) w[i] <= w[i + 1];
              w[15] <= w_new;
              sub   <= 4'd0;
              if (round == 6'd63) begin
                cnt   <= 6'd0;
                state <= S_READ;
              end
              round <= round + 6'd1;
            end else begin
              sub <= sub + 4'd1;
            end
          end

          // pipelined reads: issue byte cnt, capture byte cnt-1
          S_READ: begin
            if (cnt <= 6'd31)
              ui <= {2'b11, 1'b0, cnt[4:2], cnt[1:0]};
            else
              ui <= 8'd0;
            uio <= 8'd0;
            if (cnt >= 6'd2)
              rd <= {rd[247:0], core_uio_out};
            if (cnt == 6'd33)
              state <= S_ADD;
            cnt <= cnt + 6'd1;
          end

          S_ADD: begin
            h_out <= sum;
            done  <= 1'b1;
            for (i = 0; i < 16; i = i + 1) w[i] <= 32'd0;
            hreg  <= 256'd0;
            rd    <= 256'd0;
            scrub <= 1'b1;
            state <= S_IDLE;
          end

          default: state <= S_IDLE;
        endcase
      end
    end
  end

endmodule
