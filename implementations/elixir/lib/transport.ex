defmodule Ockam.Transport do
  @type opts :: Keyword.t()
  @type data :: iodata()
  @type reason :: term()
  @type t :: %{:__struct__ => module() | map()}

  @callback init(opts) :: opts
  @callback open(t()) :: :ok | {:error, reason}
  @callback send(t(), data, opts) :: :ok | {:error, reason}
  @callback recv(t(), opts) :: {:ok, data} | {:error, reason}
  @callback close(t()) :: :ok | {:error, reason}

  @doc """
  Encodes a message for transmission over a transport connection
  """
  @spec encode(iodata() | binary()) :: binary()
  def encode(message)

  def encode(message) when is_list(message) do
    encode(IO.iodata_to_binary(message))
  end

  def encode(message) when is_binary(message) do
    size = byte_size(message)
    <<size::big-unsigned-size(2)-unit(8), message::binary>>
  end

  @doc """
  Decodes a raw data packet received from a transport connection
  """
  @spec decode(binary()) ::
          {:ok, binary(), binary()}
          | {:more, non_neg_integer()}
          | {:error, term}
  def decode(message) do
    :erlang.decode_packet(2, message, [])
  end
end
