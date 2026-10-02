/*
 * hmac_avmm (tt07): Avalon-MM slave around hmac_ctrl (precomputed key states
 * on sha07_block and the tt07 round core), for the DE10-Nano HPS.
 *
 * Same register map and software interface as the tt05-shaman hmac_avmm, so
 * the same driver works with either:
 *
 *   byte offset  name        access  contents
 *   0x00         CTRL        W       bit0 START, bit1 CLEAR_KEY, bit2 CLEAR_DATA
 *   0x04         STATUS      R       bit0 READY, bit1 DONE, bit2 ERR, bit3 KEY_LOADED
 *   0x08         MSG_LEN     R/W     message length in bytes, 0..55
 *   0x0C         ID          R       0x484D4143 ("HMAC")
 *   0x20..0x3C   KEY[0..7]   W       32-byte key; reads return 0
 *   0x40..0x74   MSG[0..13]  W       message bytes 0..55 (byte 55 is ignored)
 *   0x80..0x9C   MAC[0..7]   R       HMAC-SHA256 of the last operation
 *
 * One clock domain, 32-bit registers, word addressing, read latency 1, no
 * wait states, little-endian within each word (word i bits [7:0] = byte 4*i).
 *
 * Key handling differs from tt05 in one way: the first START after the key
 * is written runs load_key (K^ipad and K^opad are compressed once, about 1290
 * cycles), then clears the KEY registers, so only the derived key states are
 * kept; later STARTs cost two compressions.  Writing KEY again marks a new key
 * for the next START.  KEY_LOADED means a key is written or its states are
 * loaded.  CLEAR_KEY clears the KEY registers and the key states.
 *
 * START is accepted only when READY and KEY_LOADED and MSG_LEN <= 55;
 * otherwise ERR is set.  DONE and ERR are cleared by the next accepted START
 * or a CLEAR.  KEY/MSG/MSG_LEN writes are ignored while an operation runs.
 * CLEAR_DATA clears MSG, MSG_LEN and the MAC and aborts a running operation;
 * CLEAR_KEY also aborts.  sha07_block wipes its schedule and resets the core
 * after every compression, so no message or inner-digest state remains.
 */

`default_nettype none

module hmac_avmm (
    input  wire        clk,
    input  wire        reset,            // active high, Avalon convention

    input  wire [5:0]  avs_address,      // word address
    input  wire        avs_read,
    output reg  [31:0] avs_readdata,
    input  wire        avs_write,
    input  wire [31:0] avs_writedata
);

  localparam [31:0] ID_VALUE = 32'h484D4143;

  localparam A_CTRL    = 6'h00,
             A_STATUS  = 6'h01,
             A_MSG_LEN = 6'h02,
             A_ID      = 6'h03,
             A_KEY     = 6'h08,   // ..0x0F
             A_MSG     = 6'h10,   // ..0x1D
             A_MAC     = 6'h20;   // ..0x27

  localparam P_IDLE = 2'd0,
             P_LOAD = 2'd1,       // load_key running
             P_RUN  = 2'd2;       // HMAC running

  reg [31:0] key_w [0:7];
  reg [31:0] msg_w [0:13];
  reg [5:0]  msg_len;
  reg        key_dirty;           // KEY written, states not yet computed
  reg        done_flag;
  reg        err_flag;
  reg [1:0]  phase;
  reg        load_pulse, start_pulse, abort_pulse, clear_pulse;

  wire         ctrl_ready, ctrl_key_valid, ctrl_done, ctrl_err;
  wire [255:0] ctrl_mac;

  wire key_loaded = key_dirty || ctrl_key_valid;
  wire ready = ctrl_ready && phase == P_IDLE &&
               !(load_pulse || start_pulse || abort_pulse || clear_pulse);

  wire wr_ctrl       = avs_write && avs_address == A_CTRL;
  wire do_start      = wr_ctrl && avs_writedata[0];
  wire do_clear_key  = wr_ctrl && avs_writedata[1];
  wire do_clear_data = wr_ctrl && avs_writedata[2];

  integer i;

  always @(posedge clk) begin
    if (reset) begin
      for (i = 0; i < 8; i = i + 1)  key_w[i] <= 32'd0;
      for (i = 0; i < 14; i = i + 1) msg_w[i] <= 32'd0;
      msg_len     <= 6'd0;
      key_dirty   <= 1'b0;
      done_flag   <= 1'b0;
      err_flag    <= 1'b0;
      phase       <= P_IDLE;
      load_pulse  <= 1'b0;
      start_pulse <= 1'b0;
      abort_pulse <= 1'b0;
      clear_pulse <= 1'b0;
    end else begin
      load_pulse  <= 1'b0;
      start_pulse <= 1'b0;
      abort_pulse <= 1'b0;
      clear_pulse <= 1'b0;

      if (ctrl_err) err_flag <= 1'b1;

      // operation sequencing
      if (ctrl_done) begin
        if (phase == P_LOAD) begin
          for (i = 0; i < 8; i = i + 1) key_w[i] <= 32'd0;
          key_dirty   <= 1'b0;
          start_pulse <= 1'b1;
          phase       <= P_RUN;
        end else if (phase == P_RUN) begin
          done_flag <= 1'b1;
          phase     <= P_IDLE;
        end
      end

      if (do_clear_key || do_clear_data) begin
        phase     <= P_IDLE;
        done_flag <= 1'b0;
        err_flag  <= 1'b0;
        start_pulse <= 1'b0;
        if (do_clear_key) begin
          for (i = 0; i < 8; i = i + 1) key_w[i] <= 32'd0;
          key_dirty   <= 1'b0;
          clear_pulse <= 1'b1;
        end else begin
          abort_pulse <= 1'b1;
        end
        if (do_clear_data) begin
          for (i = 0; i < 14; i = i + 1) msg_w[i] <= 32'd0;
          msg_len <= 6'd0;
        end
      end else if (do_start) begin
        if (ready && key_loaded && msg_len <= 6'd55) begin
          done_flag <= 1'b0;
          err_flag  <= 1'b0;
          if (key_dirty) begin
            load_pulse <= 1'b1;
            phase      <= P_LOAD;
          end else begin
            start_pulse <= 1'b1;
            phase       <= P_RUN;
          end
        end else begin
          err_flag <= 1'b1;
        end
      end else if (avs_write && ready) begin
        if (avs_address == A_MSG_LEN)
          msg_len <= avs_writedata[5:0];
        if (avs_address >= A_KEY && avs_address < A_KEY + 6'd8) begin
          key_w[avs_address - A_KEY] <= avs_writedata;
          key_dirty <= 1'b1;
        end
        if (avs_address >= A_MSG && avs_address < A_MSG + 6'd14)
          msg_w[avs_address - A_MSG] <= avs_writedata;
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
        avs_readdata <= {28'd0, key_loaded, err_flag, done_flag, ready};
      else if (avs_address == A_MSG_LEN)
        avs_readdata <= {26'd0, msg_len};
      else if (avs_address == A_ID)
        avs_readdata <= ID_VALUE;
      else if (avs_address >= A_MAC && avs_address < A_MAC + 6'd8)
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

  hmac_ctrl ctrl (
      .clk      (clk),
      .rst_n    (!reset),
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
