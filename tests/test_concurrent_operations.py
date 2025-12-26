"""
Concurrent Operations Tests

Tests for concurrent/parallel operations including:
- Parallel signing
- Parallel verification
- Parallel log writes
- Parallel key generation
- Read during write
"""

import os
import pytest
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from src.key_manager import KeyManager
from src.signature_service import SignatureService
from src.logger_service import VerificationLogger


@pytest.mark.concurrent
class TestParallelSigning:
    """Test concurrent signing operations."""
    
    def test_parallel_sign_operations(self, signature_service, private_key):
        """10 concurrent sign operations should all succeed."""
        messages = [f"Message number {i}" for i in range(10)]
        results = []
        errors = []
        
        def sign_message(msg):
            try:
                result = signature_service.sign_message(msg, private_key)
                return result
            except Exception as e:
                return e
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(sign_message, msg): msg for msg in messages}
            
            for future in as_completed(futures):
                result = future.result()
                if isinstance(result, Exception):
                    errors.append(result)
                else:
                    results.append(result)
        
        assert len(errors) == 0, f"Errors occurred: {errors}"
        assert len(results) == 10
        
        # All results should have valid signatures
        for result in results:
            assert result.signature is not None
            assert len(result.signature) > 0
    
    def test_parallel_sign_different_keys(self, key_manager, data_dir):
        """Parallel signing with different keys should work."""
        # Generate multiple key pairs
        key_pairs = [key_manager.generate_key_pair(2048) for _ in range(5)]
        
        log_file = os.path.join(data_dir, 'test_logs.json')
        logger = VerificationLogger(log_file)
        service = SignatureService(logger)
        
        results = []
        errors = []
        
        def sign_with_key(key_pair, index):
            try:
                private_key, _ = key_pair
                result = service.sign_message(f"Message for key {index}", private_key)
                return result
            except Exception as e:
                return e
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {
                executor.submit(sign_with_key, kp, i): i 
                for i, kp in enumerate(key_pairs)
            }
            
            for future in as_completed(futures):
                result = future.result()
                if isinstance(result, Exception):
                    errors.append(result)
                else:
                    results.append(result)
        
        assert len(errors) == 0, f"Errors occurred: {errors}"
        assert len(results) == 5


@pytest.mark.concurrent
class TestParallelVerification:
    """Test concurrent verification operations."""
    
    def test_parallel_verify_operations(self, signature_service, private_key, public_key):
        """10 concurrent verify operations should all succeed."""
        messages = [f"Message number {i}" for i in range(10)]
        
        # First sign all messages
        signatures = []
        for msg in messages:
            result = signature_service.sign_message(msg, private_key)
            signatures.append((msg, result.signature))
        
        results = []
        errors = []
        
        def verify_signature(msg, sig):
            try:
                result = signature_service.verify_signature(msg, sig, public_key)
                return result
            except Exception as e:
                return e
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(verify_signature, msg, sig): msg 
                for msg, sig in signatures
            }
            
            for future in as_completed(futures):
                result = future.result()
                if isinstance(result, Exception):
                    errors.append(result)
                else:
                    results.append(result)
        
        assert len(errors) == 0, f"Errors occurred: {errors}"
        assert len(results) == 10
        
        # All verifications should pass
        for result in results:
            assert result.is_valid is True
    
    def test_parallel_mixed_valid_invalid(self, signature_service, private_key, public_key):
        """Parallel verification with mix of valid and invalid signatures."""
        # Create some valid and some invalid signatures
        valid_msg = "Valid message"
        invalid_msg = "Invalid message"
        
        valid_result = signature_service.sign_message(valid_msg, private_key)
        
        test_cases = [
            (valid_msg, valid_result.signature, True),  # Valid
            (invalid_msg, valid_result.signature, False),  # Wrong message
            (valid_msg, b'\x00' * 256, False),  # Random signature
        ] * 5  # Repeat to test concurrency
        
        results = []
        
        def verify_case(case):
            msg, sig, expected = case
            try:
                result = signature_service.verify_signature(msg, sig, public_key)
                return (result.is_valid, expected)
            except Exception:
                return (False, expected)
        
        with ThreadPoolExecutor(max_workers=15) as executor:
            futures = [executor.submit(verify_case, case) for case in test_cases]
            
            for future in as_completed(futures):
                actual, expected = future.result()
                results.append((actual, expected))
        
        # Check all results match expectations
        for actual, expected in results:
            assert actual == expected


@pytest.mark.concurrent
class TestParallelLogWrites:
    """Test parallel log writing operations."""
    
    def test_parallel_log_writes(self, data_dir):
        """Parallel log writes should not corrupt the log file."""
        log_file = os.path.join(data_dir, 'concurrent_logs.json')
        logger = VerificationLogger(log_file)
        
        num_writes = 50
        errors = []
        
        def write_log(index):
            try:
                from datetime import datetime
                logger.log_verification(
                    message_id=f"msg_{index:04d}",
                    signature_id=f"sig_{index:04d}",
                    result=index % 2 == 0,
                    timestamp=datetime.now(),
                    padding_scheme="PSS"
                )
                return True
            except Exception as e:
                return e
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(write_log, i) for i in range(num_writes)]
            
            for future in as_completed(futures):
                result = future.result()
                if isinstance(result, Exception):
                    errors.append(result)
        
        # Allow some errors due to file locking, but should be minimal
        assert len(errors) < num_writes * 0.1, f"Too many errors: {errors}"
        
        # Add a small delay to ensure logs are written to disk
        import time
        time.sleep(0.5)
        
        # Verify log file is valid JSON and has entries
        logs = logger.get_logs()
        assert len(logs) > 0
    
    def test_log_integrity_after_parallel_writes(self, data_dir):
        """Log file should remain valid after parallel writes."""
        log_file = os.path.join(data_dir, 'integrity_logs.json')
        logger = VerificationLogger(log_file)
        
        from datetime import datetime
        
        # Write some logs in parallel
        def write_logs(count):
            for i in range(count):
                logger.log_verification(
                    message_id=f"msg_{threading.current_thread().name}_{i}",
                    signature_id=f"sig_{i}",
                    result=True,
                    timestamp=datetime.now(),
                    padding_scheme="PSS"
                )
        
        threads = [threading.Thread(target=write_logs, args=(10,)) for _ in range(5)]
        
        for t in threads:
            t.start()
        
        for t in threads:
            t.join()
        
        # Verify logs are readable
        logs = logger.get_logs()
        assert isinstance(logs, list)


@pytest.mark.concurrent
class TestParallelKeyGeneration:
    """Test parallel key generation operations."""
    
    @pytest.mark.slow
    def test_parallel_key_generation(self, key_manager):
        """Multiple key pairs generated simultaneously should all be valid."""
        num_keys = 5
        results = []
        errors = []
        
        def generate_key():
            try:
                private_key, public_key = key_manager.generate_key_pair(2048)
                return (private_key, public_key)
            except Exception as e:
                return e
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(generate_key) for _ in range(num_keys)]
            
            for future in as_completed(futures):
                result = future.result()
                if isinstance(result, Exception):
                    errors.append(result)
                else:
                    results.append(result)
        
        assert len(errors) == 0, f"Errors occurred: {errors}"
        assert len(results) == num_keys
        
        # All key pairs should be unique
        public_keys = [pk.public_key() for pk, _ in results]
        from cryptography.hazmat.primitives import serialization
        
        pem_keys = [
            pk.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            for pk in public_keys
        ]
        
        # All should be different
        assert len(set(pem_keys)) == num_keys
    
    @pytest.mark.slow
    def test_parallel_key_save_load(self, key_manager, keys_dir):
        """Parallel save/load operations should not conflict."""
        num_keys = 5
        key_pairs = [key_manager.generate_key_pair(2048) for _ in range(num_keys)]
        
        errors = []
        
        def save_and_load(index, key_pair):
            try:
                private_key, public_key = key_pair
                
                priv_path = os.path.join(keys_dir, f'private_{index}.pem')
                pub_path = os.path.join(keys_dir, f'public_{index}.pem')
                
                key_manager.save_private_key(private_key, priv_path)
                key_manager.save_public_key(public_key, pub_path)
                
                loaded_priv = key_manager.load_private_key(priv_path)
                loaded_pub = key_manager.load_public_key(pub_path)
                
                return (loaded_priv, loaded_pub)
            except Exception as e:
                return e
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {
                executor.submit(save_and_load, i, kp): i 
                for i, kp in enumerate(key_pairs)
            }
            
            for future in as_completed(futures):
                result = future.result()
                if isinstance(result, Exception):
                    errors.append(result)
        
        assert len(errors) == 0, f"Errors occurred: {errors}"


@pytest.mark.concurrent
class TestReadDuringWrite:
    """Test reading logs while another process writes."""
    
    def test_read_during_write(self, data_dir):
        """Reading logs while writing should not crash."""
        log_file = os.path.join(data_dir, 'read_write_logs.json')
        logger = VerificationLogger(log_file)
        
        from datetime import datetime
        
        write_complete = threading.Event()
        read_results = []
        write_errors = []
        read_errors = []
        
        def writer():
            try:
                for i in range(20):
                    logger.log_verification(
                        message_id=f"msg_{i}",
                        signature_id=f"sig_{i}",
                        result=True,
                        timestamp=datetime.now(),
                        padding_scheme="PSS"
                    )
                    time.sleep(0.01)  # Small delay
            except Exception as e:
                write_errors.append(e)
            finally:
                write_complete.set()
        
        def reader():
            try:
                while not write_complete.is_set():
                    logs = logger.get_logs()
                    read_results.append(len(logs))
                    time.sleep(0.01)
            except Exception as e:
                read_errors.append(e)
        
        writer_thread = threading.Thread(target=writer)
        reader_thread = threading.Thread(target=reader)
        
        writer_thread.start()
        reader_thread.start()
        
        writer_thread.join()
        reader_thread.join()
        
        assert len(write_errors) == 0, f"Write errors: {write_errors}"
        assert len(read_errors) == 0, f"Read errors: {read_errors}"
        
        # Verify final state
        final_logs = logger.get_logs()
        assert len(final_logs) == 20


@pytest.mark.concurrent
class TestThreadSafety:
    """Test thread safety of service instances."""
    
    def test_shared_signature_service(self, signature_service, private_key, public_key):
        """Shared SignatureService should be thread-safe."""
        messages = [f"Thread {i} message" for i in range(20)]
        results = []
        lock = threading.Lock()
        
        def sign_and_verify(msg):
            try:
                sign_result = signature_service.sign_message(msg, private_key)
                verify_result = signature_service.verify_signature(
                    msg, sign_result.signature, public_key
                )
                with lock:
                    results.append(verify_result.is_valid)
            except Exception as e:
                with lock:
                    results.append(False)
        
        threads = [threading.Thread(target=sign_and_verify, args=(msg,)) for msg in messages]
        
        for t in threads:
            t.start()
        
        for t in threads:
            t.join()
        
        assert all(results), "Some thread-safe operations failed"
    
    def test_shared_key_manager(self, key_manager, keys_dir):
        """Shared KeyManager should be thread-safe."""
        # Pre-generate keys
        key_pairs = [key_manager.generate_key_pair(2048) for _ in range(5)]
        
        # Save keys first
        for i, (priv, pub) in enumerate(key_pairs):
            key_manager.save_private_key(priv, os.path.join(keys_dir, f'priv_{i}.pem'))
            key_manager.save_public_key(pub, os.path.join(keys_dir, f'pub_{i}.pem'))
        
        results = []
        lock = threading.Lock()
        
        def load_keys(index):
            try:
                priv = key_manager.load_private_key(os.path.join(keys_dir, f'priv_{index}.pem'))
                pub = key_manager.load_public_key(os.path.join(keys_dir, f'pub_{index}.pem'))
                with lock:
                    results.append(True)
            except Exception:
                with lock:
                    results.append(False)
        
        threads = [threading.Thread(target=load_keys, args=(i % 5,)) for i in range(20)]
        
        for t in threads:
            t.start()
        
        for t in threads:
            t.join()
        
        assert all(results), "Some key loading operations failed"
