defmodule Ockam.Transport.TCP.Connection do
  use GenStateMachine, callback_mode: :state_functions

  require Logger

  alias Ockam.Transport.Handshake
  import Ockam.Transport, only: [encode: 1, decode: 1]

  def child_spec(args) do
    %{
      id: __MODULE__,
      start: {__MODULE__, :start_link, [args]},
      restart: :temporary,
      shutdown: 1_000,
      type: :worker
    }
  end

  defmodule State do
    defstruct [:socket, :data, :mode, :select_info, :handshake]
  end

  def start_link(_opts, socket) do
    GenStateMachine.start_link(__MODULE__, [socket])
  end

  def init([socket]) do
    data = %State{socket: socket, data: "", select_info: nil}
    {:ok, :initializing, data}
  end

  def initializing(:info, {:"$transport", :controlling_process, pid}, data) when pid == self() do
    {:ok, handshake} = Handshake.responder()
    new_data = %State{data | handshake: handshake}
    {:next_state, :handshake, new_data, [{:next_event, :internal, :receive}]}
  end

  def handshake(
        :internal,
        :receive,
        %State{socket: socket, handshake: handshake, data: prev} = data
      ) do
    case :socket.recv(socket, 0, :nowait) do
      {:ok, received} ->
        received = prev <> received

        case decode(received) do
          {:ok, message, rest} ->
            case Handshake.step(handshake, message) do
              {:ok, new_handshake, reply} ->
                :ok = :socket.send(socket, encode(reply))
                new_data = %State{data | handshake: new_handshake, data: rest}
                {:keep_state, new_data, [{:next_event, :internal, :receive}]}

              {:done, new_handshake, nil} ->
                new_data = %State{data | handshake: new_handshake, data: rest}
                {:next_state, :connected, new_data, [{:next_event, :internal, :receive}]}

              {:done, new_handshake, reply} ->
                :ok = :socket.send(socket, encode(reply))
                new_data = %State{data | handshake: new_handshake, data: rest}
                {:next_state, :connected, new_data, [{:next_event, :internal, :receive}]}

              other ->
                raise "#{inspect(other)}"
            end

          {:more, _} ->
            new_data = %State{data | data: received}
            {:keep_state, new_data, [{:next_event, :internal, :receive}]}

          {:error, reason} ->
            :socket.close(socket)
            {:stop, reason, %State{data | socket: nil}}
        end

      {:select, {:select_info, :recv, info}} ->
        {:keep_state, %State{data | select_info: info}}

      {:error, reason} ->
        :socket.close(socket)
        {:stop, reason, %State{data | socket: nil}}
    end
  end

  def handshake(:info, {:"$socket", _socket, :select, info}, %State{select_info: info} = data) do
    handshake(:internal, :receive, %State{data | select_info: nil})
  end

  def handshake(
        :info,
        {:"$socket", _socket, :abort, {info, reason}},
        %State{select_info: info} = data
      ) do
    :socket.close(data.socket)
    {:stop, reason, %State{data | socket: nil}}
  end

  def connected(:internal, :receive, %State{socket: socket, data: prev} = data) do
    case :socket.recv(socket, 0, :nowait) do
      {:ok, bin} ->
        received = prev <> bin

        case decode(received) do
          {:ok, message, rest} ->
            decrypt_and_handle_message(message, %State{data | data: rest})

          {:more, _} ->
            new_data = %State{data | data: bin}
            {:keep_state, new_data, [{:next_event, :internal, :receive}]}

          {:error, reason} ->
            :socket.close(socket)
            {:stop, reason, %State{data | socket: nil}}
        end

      {:select, {:select_info, :select, info}} ->
        {:keep_state, %State{data | select_info: info}}

      {:error, reason} ->
        :socket.close(socket)
        {:stop, reason, %State{data | socket: nil}}
    end
  end

  def connected(:info, {:"$socket", _socket, :select, info}, %State{select_info: info} = data) do
    connected(:internal, :receive, %State{data | select_info: nil})
  end

  def connected(
        :info,
        {:"$socket", _socket, :abort, {info, reason}},
        %State{select_info: info} = data
      ) do
    :socket.close(data.socket)
    {:stop, reason, %State{data | socket: nil}}
  end

  defp decrypt_and_handle_message(message, %State{handshake: hs, socket: socket} = state) do
    case Handshake.decrypt_incoming(hs, message) do
      {:ok, decrypted} ->
        handle_message(decrypted, state)

      {:error, reason} ->
        :socket.close(socket)
        {:stop, reason, %State{state | socket: nil}}
    end
  end

  defp handle_message("ACK", %State{} = _state) do
    Logger.info("Connection established and secured successfully!")
    :keep_state_and_data
  end

  defp handle_message(msg, _data) do
    {:stop, {:invalid_data, msg}}
  end

  def terminate(_reason, _state, %State{socket: nil}), do: :ok

  def terminate(_reason, _state, %State{socket: socket}) do
    :socket.close(socket)
    :ok
  end
end
