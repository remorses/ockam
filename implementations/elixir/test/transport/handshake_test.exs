defmodule Ockam.Transport.Handshake.Test do
  use ExUnit.Case, async: true
  require Logger

  alias Ockam.Transport.Handshake

  # msg_0_payload=
  # msg_0_ciphertext=358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254
  # msg_1_payload=
  # msg_1_ciphertext=64b101b1d0be5a8704bd078f9895001fc03e8e9f9522f188dd128d9846d484665393019dbd6f438795da206db0886610b26108e424142c2e9b5fd1f7ea70cde8767ce62d7e3c0e9bcefe4ab872c0505b9e824df091b74ffe10a2b32809cab21f
  # msg_2_payload=
  # msg_2_ciphertext=e610eadc4b00c17708bf223f29a66f02342fbedf6c0044736544b9271821ae40e70144cecd9d265dffdc5bb8e051c3f83db32a425e04d8f510c58a43325fbc56
  # msg_3_payload=79656c6c6f777375626d6172696e65
  # msg_3_ciphertext=9ea1da1ec3bfecfffab213e537ed1791bfa887dd9c631351b3f63d6315ab9a
  # msg_4_payload=7375626d6172696e6579656c6c6f77
  # msg_4_ciphertext=217c5111fad7afde33bd28abaff3def88a57ab50515115d23a10f28621f842
  # init_static=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
  # resp_static=0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
  # gen_init_ephemeral=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
  # gen_resp_ephemeral=4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60

  test "handshake without transport" do
    assert {:ok, %Handshake{stage: 2} = initiator, m1} = Handshake.initiator()
    assert {:ok, %Handshake{stage: 1} = responder} = Handshake.responder()
    assert {:ok, %Handshake{stage: 2} = responder2, m2} = Handshake.step(responder, m1)
    assert {:ok, %Handshake{stage: 3} = initiator2, m3} = Handshake.step(initiator, m2)
    assert {:done, %Handshake{stage: 3} = responder3, ack} = Handshake.step(responder2, m3)
    assert {:done, _initiator3, nil} = Handshake.step(initiator2, ack)
  end
end
