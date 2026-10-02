/*
 * hmac_ctrl (tt07): HMAC-SHA256 on sha07_block, with the key precomputed.
 *
 * Because sha07_block exposes the SHA-256 chaining value, the two key blocks
 * are compressed once per key:
 *
 *   load_key:  istate = compress(IV, K ^ ipad)
 *              ostate = compress(IV, K ^ opad)
 *   start:     inner  = compress(istate, msg || padding)
 *              mac    = compress(ostate, inner || padding)
 *
 * so each HMAC after load_key costs two compressions instead of four.  Keys
 * up to 32 bytes (zero-padded, as HMAC pads to 64 anyway); messages up to
 * 55 bytes so the message part is a single block.
 *
 * Secrets: the key is read from the key port only during load_key and never
 * stored; istate/ostate are key-equivalent and stay until clear_key or reset.
 * The inner digest lives only between the two compressions of an operation.
 * clear_key zeroes istate/ostate (and aborts); abort stops an operation and
 * zeroes inner and mac but keeps the key states.
 *
 * Handshake: pulse load_key or start for one cycle while ready.  done pulses
 * when an operation (load_key or start) finishes; mac is valid from that done
 * until the next start, abort or clear_key.  start without a loaded key or
 * with msg_len > 55 is refused with a one-cycle err pulse.
 */

`default_nettype none

module hmac_ctrl (
    input  wire         clk,
    input  wire         rst_n,

    input  wire [255:0] key,        // byte 0 in the top bits
    input  wire         load_key,
    input  wire [439:0] msg,        // byte 0 in the top bits
    input  wire [5:0]   msg_len,
    input  wire         start,
    input  wire         abort,
    input  wire         clear_key,

    output wire         ready,
    output reg          key_valid,
    output reg          done,
    output reg          err,
    output reg  [255:0] mac
);

  localparam [255:0] IV = {32'h6a09e667, 32'hbb67ae85, 32'h3c6ef372, 32'ha54ff53a,
                           32'h510e527f, 32'h9b05688c, 32'h1f83d9ab, 32'h5be0cd19};

  localparam S_IDLE  = 3'd0,
             S_IPAD  = 3'd1,   // compress(IV, K ^ ipad)
             S_OPAD  = 3'd2,   // compress(IV, K ^ opad)
             S_INNER = 3'd3,   // compress(istate, msg block)
             S_OUTER = 3'd4;   // compress(ostate, inner block)

  reg [2:0]   state;
  reg         launched;     // compression for this state has been started
  reg [255:0] istate, ostate, inner;
  reg [5:0]   len;

  wire         blk_busy, blk_done;
  wire [255:0] blk_out;
  reg  [255:0] blk_h;
  reg  [511:0] blk_block;

  assign ready = (state == S_IDLE);

  // ---- blocks --------------------------------------------------------------
  wire [511:0] key_block = {key, 256'd0};
  wire [511:0] ipad_block = key_block ^ {64{8'h36}};
  wire [511:0] opad_block = key_block ^ {64{8'h5c}};

  wire [9:0] msg_bits = {4'd0, len} * 10'd8 + 10'd512;   // 64-byte key block + msg
  reg  [511:0] msg_block;
  integer j;
  always @* begin
    msg_block = 512'd0;
    for (j = 0; j < 55; j = j + 1)
      if (j < len)
        msg_block[511 - 8*j -: 8] = msg[439 - 8*j -: 8];
    msg_block[511 - 8*len -: 8] = 8'h80;
    msg_block[15:0] = {6'd0, msg_bits};
  end

  // inner || 0x80 || zeros || length (64 + 32 bytes = 768 bits)
  wire [511:0] inner_block = {inner, 8'h80, 232'd0, 16'd768};

  always @* begin
    case (state)
      S_IPAD:  begin blk_h = IV;     blk_block = ipad_block;  end
      S_OPAD:  begin blk_h = IV;     blk_block = opad_block;  end
      S_INNER: begin blk_h = istate; blk_block = msg_block;   end
      S_OUTER: begin blk_h = ostate; blk_block = inner_block; end
      default: begin blk_h = 256'd0; blk_block = 512'd0;     end
    endcase
  end

  wire blk_start = (state != S_IDLE) && !launched;
  wire blk_abort = abort || clear_key;

  sha07_block blk (
      .clk  (clk),
      .rst_n(rst_n),
      .start(blk_start),
      .abort(blk_abort),
      .h_in (blk_h),
      .block(blk_block),
      .busy (blk_busy),
      .done (blk_done),
      .h_out(blk_out)
  );

  // ---- control ---------------------------------------------------------------
  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      state     <= S_IDLE;
      launched  <= 1'b0;
      istate    <= 256'd0;
      ostate    <= 256'd0;
      inner     <= 256'd0;
      mac       <= 256'd0;
      len       <= 6'd0;
      key_valid <= 1'b0;
      done      <= 1'b0;
      err       <= 1'b0;
    end else begin
      done <= 1'b0;
      err  <= 1'b0;

      if (clear_key || abort) begin
        state    <= S_IDLE;
        launched <= 1'b0;
        inner    <= 256'd0;
        mac      <= 256'd0;
        if (clear_key) begin
          istate    <= 256'd0;
          ostate    <= 256'd0;
          key_valid <= 1'b0;
        end
      end else begin
        if (blk_start)
          launched <= 1'b1;

        case (state)
          S_IDLE: begin
            if (load_key) begin
              key_valid <= 1'b0;
              istate    <= 256'd0;
              ostate    <= 256'd0;
              state     <= S_IPAD;
            end else if (start) begin
              if (!key_valid || msg_len > 6'd55) begin
                err <= 1'b1;
              end else begin
                len   <= msg_len;
                mac   <= 256'd0;
                state <= S_INNER;
              end
            end
          end

          S_IPAD: if (blk_done) begin
            istate   <= blk_out;
            launched <= 1'b0;
            state    <= S_OPAD;
          end

          S_OPAD: if (blk_done) begin
            ostate    <= blk_out;
            key_valid <= 1'b1;
            launched  <= 1'b0;
            done      <= 1'b1;
            state     <= S_IDLE;
          end

          S_INNER: if (blk_done) begin
            inner    <= blk_out;
            launched <= 1'b0;
            state    <= S_OUTER;
          end

          S_OUTER: begin
            if (launched)
              inner <= 256'd0;   // copied into sha07_block's schedule window
            if (blk_done) begin
              mac      <= blk_out;
              launched <= 1'b0;
              done     <= 1'b1;
              state    <= S_IDLE;
            end
          end

          default: state <= S_IDLE;
        endcase
      end
    end
  end

endmodule
