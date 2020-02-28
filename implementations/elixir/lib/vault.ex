defmodule Ockam.Vault do
  require Logger

  @type key_type :: :static | :ephemeral
  @type key_id :: binary()
  @type pubkey :: binary()
  @type privkey :: binary()
  @type salt :: binary()

  def init_vault!(config) when is_list(config) do
    with {_, {:ok, curve}} <- {:curve, Keyword.fetch(config, :curve)},
         _ = :ets.new(__MODULE__.Keys, [:named_table, :set, :public]),
         {_, :ok} <- {:vault, init_vault(curve)} do
      case Keyword.get(config, :keypairs, []) do
        [] ->
          :ok

        kps when is_list(kps) ->
          Logger.info("Registering configured static keys..")

          for {name, meta} <- kps do
            name = Atom.to_string(name)
            dir = Keyword.get(meta, :path, Application.app_dir(:ockam, :priv))
            Logger.debug("Registering key '#{name}' in directory '#{dir}'")
            pubkey_path = Path.join(dir, "#{name}.pub")
            privkey_path = Path.join(dir, "#{name}")
            pubkey = File.read!(pubkey_path)
            privkey = File.read!(privkey_path)
            true = :ets.insert_new(__MODULE__.Keys, {name, pubkey, privkey})
          end

          :ok
      end

      Logger.info("Vault initialized!")
    else
      error ->
        exit(error)
    end
  end

  defdelegate init_vault(curve), to: Ockam.Vault.NIF

  def random() do
    bytes = :crypto.strong_rand_bytes(8)
    {:ok, :crypto.bytes_to_integer(bytes)}
  end

  @spec key_gen_static(key_id) :: {:ok, {key_id, pubkey, privkey}}
  def key_gen_static(key_id) do
    case :ets.lookup(__MODULE__.Keys, key_id) do
      [] ->
        {pubkey, privkey} = :crypto.generate_key(:ecdh, :x25519)
        true = :ets.insert_new(__MODULE__.Keys, {key_id, pubkey, privkey})
        {:ok, {key_id, pubkey, privkey}}

      [{^key_id, _pubkey, _privkey} = found] ->
        {:ok, found}
    end
  end

  @spec key_gen_ephemeral() :: {:ok, {pubkey, privkey}}
  def key_gen_ephemeral() do
    {pubkey, privkey} = :crypto.generate_key(:ecdh, :x25519)
    {:ok, {pubkey, privkey}}
  end

  def get_public_key(:static, key_id) do
    case :ets.lookup(__MODULE__.Keys, key_id) do
      [] ->
        {:error, :not_found}

      [{^key_id, pubkey, _privkey}] ->
        {:ok, pubkey}
    end
  end

  def get_public_key(:ephemeral, _key_id) do
    {:error, {:invalid_key_type, :ephemeral}}
  end

  defdelegate write_public_key(key_type, privkey), to: Ockam.Vault.NIF

  def sha256(data) do
    {:ok, :crypto.hash(:sha256, data)}
  end

  def ecdh(key_type, pubkey, privkey) when key_type in [:x25519] do
    {:ok, :crypto.compute_key(:ecdh, pubkey, privkey, key_type)}
  end

  @doc """
  Performs the hkdf operation on the given input key material
  """
  @spec hkdf(salt(), ikm :: binary(), info :: binary(), len :: integer()) ::
          {:ok, okm :: binary()} | {:error, atom()}
  def hkdf(salt, ikm, info, len) do
    salt =
      case salt do
        s when s in [nil, ""] -> <<0::size(256)-unit(1)>>
        s -> s
      end

    ikm = if is_nil(ikm), do: "", else: ikm
    info = if is_nil(info), do: "", else: info
    prk = :crypto.hmac(:sha256, salt, ikm)
    hkdf_expand(:sha256, prk, info, len)
  end

  defp hkdf_expand(:sha256, prk, info, len) when is_integer(len) do
    case {len, hkdf_max_length(:sha256)} do
      {l, _max} when l <= 0 ->
        {:error, :derived_length_leq_zero}

      {l, max_l} when l <= max_l ->
        <<okm::binary-size(len), _::binary>> =
          hkdf_expand(
            :sha256,
            prk,
            info,
            # current iteration
            1,
            # num iterations left
            calc_iters(l, :sha256),
            "",
            ""
          )

        {:ok, okm}

      _ ->
        {:error, :max_derived_length_exceeded}
    end
  end

  defp hkdf_expand(_algo, _prk, _info, i, n, _prev, acc) when i > n, do: acc

  defp hkdf_expand(algo, prk, info, i, n, prev, acc) do
    ti = :crypto.hmac(algo, prk, prev <> info <> <<i::size(8)>>)
    hkdf_expand(algo, prk, info, i + 1, n, ti, acc <> ti)
  end

  defp hkdf_max_length(:sha256) do
    :erlang.bsr(256, 3) * 255
  end

  defp calc_iters(len, :sha256) do
    hash_len = :erlang.bsr(256, 3)
    t = div(len, hash_len)

    case rem(len, hash_len) do
      0 ->
        t

      _ ->
        t + 1
    end
  end

  @tag_size 16
  @spec aes_gcm_encrypt(binary(), binary(), binary(), binary()) ::
          {:ok, {ciphertext :: binary, tag :: binary}} | {:error, term}
  def aes_gcm_encrypt(input, key, iv, aad) when is_binary(key) do
    {:ok, :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, input, aad, @tag_size, true)}
  catch
    :error, {tag, {_file, _line}, description} ->
      {:error, {tag, description}}
  end

  def aes_gcm_decrypt(ciphertext, key, iv, aad, tag) when is_binary(key) do
    case :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, ciphertext, aad, tag, false) do
      :error ->
        {:error, {:decrypt, "decryption failed"}}

      plaintext ->
        {:ok, plaintext}
    end
  catch
    :error, {tag, {_file, _line}, description} ->
      {:error, {tag, description}}
  end
end
