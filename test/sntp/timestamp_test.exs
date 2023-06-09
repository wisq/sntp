defmodule SNTP.TimestampTest do
  use ExUnit.Case, async: true
  alias SNTP.Timestamp

  test "parse a real world packet" do
    socket = %SNTP.Socket{
      errors: [],
      host: '0.debian.pool.ntp.org',
      host_port: 123,
      message: %SNTP.NTPMessage{
        data:
          <<36, 2, 3, 232, 0, 0, 19, 220, 0, 0, 11, 104, 195, 219, 205, 18, 232, 45, 109, 97, 228,
            52, 89, 177, 232, 45, 116, 160, 121, 219, 34, 209, 232, 45, 116, 160, 134, 24, 161,
            139, 232, 45, 116, 160, 134, 30, 98, 149>>,
        sent_at: 1_686_304_288_476,
        received_at: 1_686_304_288_485,
        ip: {216, 6, 2, 70}
      },
      port: nil,
      resolve_reference: false,
      timeout: :infinity
    }

    assert %SNTP.Timestamp{} = ts = Timestamp.parse(socket)
    assert ts.d == 8.912109375
    assert ts.originate_timestamp == 1_686_304_288_476.0
    assert ts.transmit_timestamp == 1_686_304_288_523.9011
    assert ts.receive_timestamp == 1_686_304_288_523.8132
    assert ts.errors == []
  end

  test "parse a packet from the year 2046" do
    socket = %SNTP.Socket{
      errors: [],
      host: 'pool.ntp.org',
      host_port: 123,
      message: %SNTP.NTPMessage{
        data:
          <<36, 3, 0, 231, 0, 0, 7, 233, 0, 0, 1, 78, 10, 70, 8, 122, 232, 45, 119, 250, 232, 17,
            225, 161, 20, 45, 120, 114, 165, 227, 83, 248, 20, 45, 120, 114, 177, 91, 154, 91, 20,
            45, 120, 114, 177, 95, 228, 173>>,
        sent_at: 2_424_502_770_648,
        received_at: 2_424_502_770_659,
        ip: {162, 159, 200, 123}
      },
      port: nil,
      resolve_reference: false,
      timeout: :infinity
    }

    assert %SNTP.Timestamp{} = ts = Timestamp.parse(socket)
    assert ts.originate_timestamp == 2_424_502_770_648.0
    assert ts.transmit_timestamp == 2_424_502_770_692.8696
    assert ts.receive_timestamp == 2_424_502_770_692.8037
    assert ts.errors == []
  end
end
