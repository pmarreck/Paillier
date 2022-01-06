#!/usr/bin/env ruby

=begin
	This module tests the higher-level Paillier functionality that
	users will be exposed to. Lower level tests should be conducted
	in test_primes and test_paillier_math.
=end

require_relative '../paillier'
require 'test/unit'

class TestPaillier < Test::Unit::TestCase #:nodoc:
	def setup()
		# We only need to make a keypair once, and can re-use it for all
		# the tests. To pull this off we use a module variable.
		unless( defined?(@@priv) and defined?(@@pub) )
			puts "Generating keypair..."
			(@@priv, @@pub) = Paillier.generateKeypair(2048)
		end
	end

	def testSanity()
		x = 3
		cx = Paillier.encrypt(@@pub, x)
		dx = Paillier.decrypt(@@priv, @@pub, cx)
		assert_not_equal(x, cx)
		assert_equal(x, dx)
	end

	def testSanityWithStrings()
		x = "3"
		cx = Paillier.encrypt(@@pub, x)
		dx = Paillier.decrypt(@@priv, @@pub, cx.to_s)
		assert_not_equal(x.to_i, cx)
		assert_equal(x.to_i, dx)
	end

	def testCryptoAddition()
		x = 3
		y = 5
		cx = Paillier.encrypt(@@pub, x)
		cy = Paillier.encrypt(@@pub, y)
		cz = Paillier.eAdd(@@pub, cx, cy)
		z = Paillier.decrypt(@@priv, @@pub, cz)
		assert_equal(x + y, z)
	end

	def testCryptoVeryLargeAddition()
		# this seems to be about the largest input the algo will take, it will break on 2**2048
		# Interestingly, with X and Y values of 2**2047-10 and 4 (or 2**2047-5 and 0, etc.),
		# the test passing becomes nondeterministic/flagging.
		# What I presume is happening is some sub-decimal-digit error is being introduced by
		# the encryption, so to enable addition with negative numbers ("integers") I will
		# take half the value of 2**2047 (2**2046) and then add that before encrypting
		# (so the "intermediate value" is always zero or positive, assuming the lower bound of
		# -2**2046 is not exceeded)
		# and then subtract it again once the addition is complete.
		# Note that values approaching the limit of +/- 2**2046 may not be accurate, or may error,
		# as a result.
		x = 2**2047-10
		y = 1
		cx = Paillier.encrypt(@@pub, x)
		cy = Paillier.encrypt(@@pub, y)
		cz = Paillier.eAdd(@@pub, cx, cy)
		z = Paillier.decrypt(@@priv, @@pub, cz)
		assert_equal(x + y, z)
	end

	#TODO: Implement integer operations by first adding half Paillier.MAXVAL to input
	# before encryption, then subtracting it again after decryption

	def testConstAddition()
		x = 3
		cx = Paillier.encrypt(@@pub, x)
		cy = Paillier.eAddConst(@@pub, cx, 2)
		y = Paillier.decrypt(@@priv, @@pub, cy)
		assert_equal(x + 2, y)
	end

	def testConstNegativeAddition() # also known as "subtraction" :)
	  x = 5
	  y = -12
	  cx = Paillier.integer_encrypt(@@pub, x)
	  cy = Paillier.integer_encrypt(@@pub, y)
	  csum = Paillier.eAdd(@@pub, cx, cy)
	  psum = Paillier.integer_decrypt(@@priv, @@pub, csum)
	  sum = psum.to_i
	  assert_equal(-7, sum)
	end

	def testConstMultiply()
		x = 3
		cx = Paillier.encrypt(@@pub, x)
		cy = Paillier.eMulConst(@@pub, cx, 2)
		y = Paillier.decrypt(@@priv, @@pub, cy)
		assert_equal(x * 2, y)
	end

	def testAverageWithCountKnown()
		nums = [15, 99, 54, 252, 13, 128]
		czero = Paillier.encrypt(@@pub, 0)
		cnums = nums.map { |i| Paillier.encrypt(@@pub, i) }
		cavg, precision = Paillier.eMean(@@pub, cnums)
		avg = Paillier.decrypt(@@priv, @@pub, cavg)
		# puts avg.to_i
		avg = avg.to_i.to_f / precision
		# This should actually be 93.5 exactly but due to integer rounding, this is expected
		# pending further "mathing" :)
		assert_equal(93.500187, avg)
		# So the only other bit of information you'd have to pass back to the client with the encrypted mean result is the precision value you used
		# so they could then divide by that on their end (after decrypting) to get the true mean (or close to it).
		# So this is how you can compute the mean of some encrypted numbers for someone and never learn the numbers, just their count!
	end

	# def testCompareTwoEncryptedNumbers()
	# 	lower = 505
	# 	higher = 506
	# 	assert lower < higher
	# 	clower = Paillier.encrypt(@@pub, lower)
	# 	chigher = Paillier.encrypt(@@pub, higher)
	# 	assert Paillier.eLessThan(@@pub, lower, higher)
	# 	assert Paillier.eGreaterThan(@@pub, higher, lower)
	# end

	def testValidSignature()
		sig = Paillier.sign(@@priv, @@pub, 1000)
		valid = Paillier.validSignature?(@@pub, 1000, sig)
		assert_equal(valid, true)
	end

	def testInvalidSignature()
		sig = Paillier.sign(@@priv, @@pub, 1000)
		valid = Paillier.validSignature?(@@pub, 666, sig)
		assert_equal(valid, false)
	end

	def testSignatureSerialization()
		sig = Paillier.sign(@@priv, @@pub, 1000)
		stringsig = sig.to_s
		newsig = Paillier::Signature.from_s(stringsig)
		valid = Paillier.validSignature?(@@pub, 1000, newsig)
		assert_equal(valid, true)
	end

	def testPublicKeySerialization()
		keystring = @@pub.to_s
		newPubkey = Paillier::PublicKey.from_s(keystring)
		assert_equal(@@pub.n, newPubkey.n)
	end

	def testPrivateKeySerialization()
		keystring = @@priv.to_s
		newPrivkey = Paillier::PrivateKey.from_s(keystring)
		assert_equal(@@priv.l, newPrivkey.l)
		assert_equal(@@priv.m, newPrivkey.m)
	end
end
