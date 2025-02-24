defmodule SNTPTest do
  use ExUnit.Case

  # doctest SNTP

  @tag external: true
  test "returns consistent result over multiple tries" do
    {:ok, %{t: t1}} = SNTP.time()
    {:ok, %{t: t2}} = SNTP.time()
    assert Kernel.abs(t1 - t2) < 200
  end

  @tag external: true
  test "resolves reference IP" do
    # Not all hosts have a reference host, but trying four different ones should usually work.
    assert Enum.any?(0..3, fn n ->
             case SNTP.time(host: "#{n}.pool.ntp.org", timeout: 1000, resolve_reference: true) do
               {:ok, time} -> !is_nil(time.reference_host)
               {:error, _} -> false
             end
           end)
  end

  @tag external: true
  test "times out on no response" do
    {:error, errors} = SNTP.time(host: 'ntp.exnet.com', port: 123, timeout: 100)
    assert errors[:timeout] == "Server Timeout after 100"
  end

  @tag external: true
  test "invalid host" do
    {:error, errors} = SNTP.time(host: 'time.blackhole.nowhere', port: 123, timeout: 100)
    assert errors[:udp_send] == :nxdomain
  end
end
