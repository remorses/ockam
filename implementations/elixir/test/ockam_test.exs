defmodule OckamTest do
  use ExUnit.Case, async: true
  require Logger

  alias Ockam.Transport.Handshake
  import Ockam.Transport, only: [encode: 1, decode: 1]

  setup context do
    if transport = context[:transport] do
      name = Map.fetch!(context, :transport_name)
      meta = [name: name]
      config = Map.get(context, :transport_config, [])
      pid = start_supervised!({transport, [meta, config]})
      {:ok, [pid: pid, config: config]}
    else
      {:ok, []}
    end
  end

  @tag transport: Ockam.Transport.TCP
  @tag transport_name: :tcp_4000
  @tag transport_config: [listen_address: "0.0.0.0", listen_port: 4000]
  test "tcp transport", %{config: config} do
    port = config[:listen_port]
    {:ok, socket} = :socket.open(:inet, :stream, :tcp)
    {:ok, handshake, m1} = Handshake.initiator()

    Process.sleep(1_000)

    with :ok <- :socket.setopt(socket, :socket, :keepalive, true),
         {:ok, _} <- :socket.bind(socket, :any),
         :ok = :socket.connect(socket, %{family: :inet, addr: :loopback, port: port}) do
      assert :ok = :socket.send(socket, encode(m1))
      assert {:ok, data} = :socket.recv(socket, 0)
      assert {:ok, decoded, ""} = decode(data)
      assert {:ok, handshake, m2} = Handshake.step(handshake, decoded)
      assert :ok = :socket.send(socket, encode(m2))
      assert {:ok, data} = :socket.recv(socket, 0)
      assert {:ok, decoded, ""} = decode(data)
      assert {:done, handshake, nil} = Handshake.step(handshake, decoded)

      :socket.close(socket)
    else
      {:error, reason} ->
        exit({:error, reason})
        :socket.close(socket)
    end
  end
end
