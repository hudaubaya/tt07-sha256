/*
 * hmac_avmm (tt07): Avalon-MM slave around hmac_ctrl (precomputed key states
 * on sha07_block and the tt07 round core), for the DE10-Nano HPS.
 *
 * Same register map and software interface as the tt05-shaman hmac_avmm, so
 * the same driver works with either:
 *
 *   byte offset  name        access  contents
 *   0x00         CTRL        W       bit0 START, bit1 CLEAR_KEY, bit2 CLEAR_DATA
 *   0x04         STATUS      R       bit0 READY, bit1 DONE, bit2 ERR, bit3 KEY_LOADED,
 *                                    bit4 TAMPERED
 *   0x08         MSG_LEN     R/W     message length in bytes, 0..55
 *   0x0C         ID          R       0x484D4143 ("HMAC")
 *   0x20..0x3C   KEY[0..7]   W       32-byte key; reads return 0
 *   0x40..0x74   MSG[0..13]  W       message bytes 0..55 (byte 55 is ignored)
 *   0x80..0x9C   MAC[0..7]   R       HMAC-SHA256 of the last operation
 *
 * One clock domain, 32-bit registers, word addressing, read latency 1, no
 * wait states, little-endian within each word (word i bits [7:0] = byte 4*i).
 *
 * Key handling: the first START after the key is written runs load_key (K^ipad
 * and K^opad are compressed once), then clears the KEY registers, so only the
 * derived key states (istate/ostate in hmac_ctrl) are kept; later STARTs cost
 * two compressions.  Writing KEY again marks a new key for the next START.
 * KEY_LOADED means a key is written or its states are loaded.  CLEAR_KEY
 * clears the KEY registers and the key states.
 *
 * START is accepted only when READY and KEY_LOADED and MSG_LEN <= 55;
 * otherwise ERR is set.  DONE and ERR are cleared by the next accepted START
 * or a CLEAR.  KEY/MSG/MSG_LEN writes are ignored while an operation runs.
 * CLEAR_DATA clears MSG, MSG_LEN and the MAC and aborts a running operation;
 * CLEAR_KEY also aborts.
 *
 * Constant time: DONE is raised a fixed number of cycles after the clock edge
 * that accepts START, whatever the key or message: LATENCY_LOADED when the
 * key states are already loaded, LATENCY_FRESH when the key was written since
 * (precompute + HMAC).  READY stays low and MAC reads return 0 until then.
 * (If hmac_ctrl were ever later, DONE would wait for it and lat_overrun would
 * be set; the tests check it never is.)
 *
 * Tamper: tamper_n (active-low push-button) is synchronised by two flip-flops.
 * The synchronised signal clears the KEY registers asynchronously and holds
 * hmac_ctrl (and with it sha07_block and the core) in asynchronous reset,
 * which clears istate/ostate; otherwise it acts exactly like CLEAR_KEY.  From
 * the first clock edge that samples tamper_n low, all state is cleared within
 * 3 cycles.  STATUS.TAMPERED stays set until reset.
 *
 * Illegal FSM states: the operation FSM's default branch performs the
 * CLEAR_KEY action (the register is marked syn_encoding "safe" so synthesis
 * keeps the recovery logic).
 *
 * sha07_block wipes its schedule and resets the core after every compression,
 * so no message or inner-digest state remains after an operation.
 */

`default_nettype none

module hmac_avmm (
    input  wire        clk,
    input  wire        reset,            // active high, Avalon convention
    input  wire        tamper_n,         // active-low tamper push-button, asynchronous

    input  wire [5:0]  avs_address,      // word address
    input  wire        avs_read,
    output reg  [31:0] avs_readdata,
    input  wire        avs_write,
    input  wire [31:0] avs_writedata
);

  localparam [31:0] ID_VALUE = 32'h484D4143;

  // START-accept edge to DONE, in cycles.  hmac_ctrl takes 1290 cycles per
  // load_key and per HMAC, plus the pulse/handover cycles.
  localparam [11:0] LATENCY_LOADED = 12'd1320;
  localparam [11:0] LATENCY_FRESH  = 12'd2620;

  localparam A_CTRL    = 6'h00,
             A_STATUS  = 6'h01,
             A_MSG_LEN = 6'h02,
             A_ID      = 6'h03,
             A_KEY     = 6'h08,   // ..0x0F
             A_MSG     = 6'h10,   // ..0x1D
             A_MAC     = 6'h20;   // ..0x27

  localparam [1:0] P_IDLE = 2'd0,
                   P_LOAD = 2'd1,  // load_key running
                   P_RUN  = 2'd2;  // HMAC running; 2'd3 is illegal

  reg [31:0] key_w [0:7];
  reg [31:0] msg_w [0:13];
  reg [5:0]  msg_len;
  reg        key_dirty;           // KEY written, states not yet computed
  reg        done_flag;
  reg        err_flag;
  reg        tampered;
  (* syn_encoding = "safe" *) reg [1:0] phase;
  reg        load_pulse, start_pulse, abort_pulse, clear_pulse;
  reg [11:0] cnt;                 // cycles since START was accepted
  reg [11:0] deadline;            // LATENCY_LOADED or LATENCY_FRESH
  reg        ctrl_finished;       // the HMAC itself has finished
  reg        lat_overrun;         // debug: hmac_ctrl later than the deadline
  reg        tamper_ff1, tamper_ff2;

  wire         ctrl_ready, ctrl_key_valid, ctrl_done, ctrl_err;
  wire [255:0] ctrl_mac;

  wire tamper     = tamper_ff2;
  wire key_loaded = key_dirty || ctrl_key_valid;
  wire ready = ctrl_ready && phase == P_IDLE && !tamper &&
               !(load_pulse || start_pulse || abort_pulse || clear_pulse);

  wire wr_ctrl       = avs_write && avs_address == A_CTRL;
  wire do_start      = wr_ctrl && avs_writedata[0];
  wire do_clear_data = wr_ctrl && avs_writedata[2];
  wire illegal_phase = phase == 2'd3;
  // the CLEAR_KEY action: bus request, tamper or illegal FSM state
  wire clear_key     = (wr_ctrl && avs_writedata[1]) || tamper || illegal_phase;

  integer i;

  // ---- tamper synchroniser -------------------------------------------------
  always @(posedge clk) begin
    if (reset) begin
      tamper_ff1 <= 1'b0;
      tamper_ff2 <= 1'b0;
    end else begin
      tamper_ff1 <= !tamper_n;
      tamper_ff2 <= tamper_ff1;
    end
  end

  // ---- key registers: cleared asynchronously by the synchronised tamper ----
  always @(posedge clk or posedge tamper) begin
    if (tamper) begin
      for (i = 0; i < 8; i = i + 1) key_w[i] <= 32'd0;
      key_dirty <= 1'b0;
    end else if (reset || clear_key || (ctrl_done && phase == P_LOAD)) begin
      // the load_key result is in istate/ostate: the raw key is not kept
      for (i = 0; i < 8; i = i + 1) key_w[i] <= 32'd0;
      key_dirty <= 1'b0;
    end else if (avs_write && ready && avs_address >= A_KEY && avs_address < A_KEY + 6'd8) begin
      key_w[avs_address - A_KEY] <= avs_writedata;
      key_dirty <= 1'b1;
    end
  end

  // ---- control ---------------------------------------------------------------
  always @(posedge clk) begin
    if (reset) begin
      for (i = 0; i < 14; i = i + 1) msg_w[i] <= 32'd0;
      msg_len       <= 6'd0;
      done_flag     <= 1'b0;
      err_flag      <= 1'b0;
      tampered      <= 1'b0;
      phase         <= P_IDLE;
      load_pulse    <= 1'b0;
      start_pulse   <= 1'b0;
      abort_pulse   <= 1'b0;
      clear_pulse   <= 1'b0;
      cnt           <= 12'd0;
      deadline      <= 12'd0;
      ctrl_finished <= 1'b0;
      lat_overrun   <= 1'b0;
    end else begin
      load_pulse  <= 1'b0;
      start_pulse <= 1'b0;
      abort_pulse <= 1'b0;
      clear_pulse <= 1'b0;
      if (tamper) tampered <= 1'b1;

      if (clear_key || do_clear_data) begin
        phase         <= P_IDLE;
        cnt           <= 12'd0;
        deadline      <= 12'd0;
        ctrl_finished <= 1'b0;
        done_flag     <= 1'b0;
        err_flag      <= 1'b0;
        if (clear_key)
          clear_pulse <= 1'b1;   // zeroes istate/ostate (also held in reset by tamper)
        else
          abort_pulse <= 1'b1;
        if (do_clear_data) begin
          for (i = 0; i < 14; i = i + 1) msg_w[i] <= 32'd0;
          msg_len <= 6'd0;
        end
      end else begin
        if (phase != P_IDLE) begin
          if (do_start)
            err_flag <= 1'b1;               // START while busy is refused
          if (ctrl_err)
            err_flag <= 1'b1;
          if (cnt != deadline)
            cnt <= cnt + 12'd1;
        end

        case (phase)
          P_IDLE: begin
            if (do_start) begin
              if (ready && key_loaded && msg_len <= 6'd55) begin
                done_flag     <= 1'b0;
                err_flag      <= 1'b0;
                cnt           <= 12'd1;
                ctrl_finished <= 1'b0;
                if (key_dirty) begin
                  load_pulse <= 1'b1;
                  deadline   <= LATENCY_FRESH;
                  phase      <= P_LOAD;
                end else begin
                  start_pulse <= 1'b1;
                  deadline    <= LATENCY_LOADED;
                  phase       <= P_RUN;
                end
              end else begin
                err_flag <= 1'b1;
              end
            end else if (avs_write && ready) begin
              if (avs_address == A_MSG_LEN)
                msg_len <= avs_writedata[5:0];
              if (avs_address >= A_MSG && avs_address < A_MSG + 6'd14)
                msg_w[avs_address - A_MSG] <= avs_writedata;
            end
          end

          P_LOAD: begin
            if (ctrl_done) begin
              start_pulse <= 1'b1;
              phase       <= P_RUN;
            end
          end

          P_RUN: begin
            if (ctrl_done)
              ctrl_finished <= 1'b1;
            if (cnt == deadline) begin
              if (ctrl_finished) begin
                done_flag <= 1'b1;
                phase     <= P_IDLE;
              end else begin
                lat_overrun <= 1'b1;
              end
            end
          end

          default: ;  // illegal: clear_key is already asserted (illegal_phase)
        endcase
      end
    end
  end

  // ---- read path (latency 1) ----------------------------------------------
  wire [255:0] mac_le;      // MAC byte 4*i in mac word i bits [7:0]
  genvar g;
  generate
    for (g = 0; g < 32; g = g + 1) begin : g_mac
      assign mac_le[8*g +: 8] = ctrl_mac[255 - 8*g -: 8];
    end
  endgenerate

  always @(posedge clk) begin
    if (reset) begin
      avs_readdata <= 32'd0;
    end else if (avs_read) begin
      avs_readdata <= 32'd0;
      if (avs_address == A_STATUS)
        avs_readdata <= {27'd0, tampered, key_loaded, err_flag, done_flag, ready};
      else if (avs_address == A_MSG_LEN)
        avs_readdata <= {26'd0, msg_len};
      else if (avs_address == A_ID)
        avs_readdata <= ID_VALUE;
      else if (avs_address >= A_MAC && avs_address < A_MAC + 6'd8 && done_flag)
        avs_readdata <= mac_le[32*(avs_address - A_MAC) +: 32];
    end
  end

  // ---- byte-order conversion to hmac_ctrl (byte 0 in the top bits) --------
  wire [255:0] key_be;
  wire [439:0] msg_be;
  generate
    for (g = 0; g < 32; g = g + 1) begin : g_key
      assign key_be[255 - 8*g -: 8] = key_w[g / 4][8*(g % 4) +: 8];
    end
    for (g = 0; g < 55; g = g + 1) begin : g_msg
      assign msg_be[439 - 8*g -: 8] = msg_w[g / 4][8*(g % 4) +: 8];
    end
  endgenerate

  // tamper is a flip-flop output, so it is safe in this asynchronous reset
  hmac_ctrl ctrl (
      .clk      (clk),
      .rst_n    (!reset && !tamper),
      .key      (key_be),
      .load_key (load_pulse),
      .msg      (msg_be),
      .msg_len  (msg_len),
      .start    (start_pulse),
      .abort    (abort_pulse),
      .clear_key(clear_pulse),
      .ready    (ctrl_ready),
      .key_valid(ctrl_key_valid),
      .done     (ctrl_done),
      .err      (ctrl_err),
      .mac      (ctrl_mac)
  );

endmodule
