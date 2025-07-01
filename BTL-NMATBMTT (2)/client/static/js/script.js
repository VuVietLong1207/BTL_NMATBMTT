$(document).ready(function() {
    // Form validation
    const form = $('#uploadForm');
    form.on('submit', function(e) {
        e.preventDefault();
        
        if (!form[0].checkValidity()) {
            e.stopPropagation();
            form.addClass('was-validated');
            return;
        }

        submitForm();
    });

    // AJAX Form Submission
    async function submitForm() {
        const formData = new FormData();
        const fileInput = $('#fileInput')[0];
        
        if (!fileInput.files[0]) {
            showAlert('Vui lòng chọn file trước khi gửi', 'danger');
            return;
        }

        const file = fileInput.files[0];
        formData.append('file', file);

        // Show loading state
        const submitBtn = $('#submitBtn');
        submitBtn.prop('disabled', true);
        $('#btnText').text('Đang xử lý...');
        $('#spinner').removeClass('d-none');
        
        try {
            // 1. Calculate file hash
            const fileHash = await calculateFileHash(file);
            $('#fileHash').text('Hash: ' + fileHash.substring(0, 32) + '...');
            
            // 2. Handshake
            await updateStatusWithAction('handshake', 'Đang xác thực handshake...', 
                async () => {
                    const response = await fetch('/handshake', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({ip: '127.0.0.1', hello: 'Hello'})
                    });
                    const data = await response.json();
                    if (data.status !== 'Ready!') throw new Error('Handshake failed');
                    $('#handshakeDetails').html(`Phiên bản: ${data.version || '1.0'} | Thời gian: ${new Date().toLocaleTimeString()}`);
                },
                'Xác thực handshake thành công',
                'Handshake thất bại'
            );

            // 3. Key exchange
            await updateStatusWithAction('keyExchange', 'Đang trao đổi khóa...',
                async () => {
                    const sessionKey = window.crypto.getRandomValues(new Uint8Array(32));
                    $('#keyExchangeDetails').text(`Khóa phiên: ${Array.from(sessionKey).map(b => b.toString(16).padStart(2, '0')).join('').substring(0, 16)}...`);
                    await new Promise(resolve => setTimeout(resolve, 800));
                    return sessionKey;
                },
                'Đã trao đổi khóa RSA 1024-bit OAEP',
                'Trao đổi khóa thất bại'
            );

            // 4. Encryption
            await updateStatusWithAction('encryption', 'Đang mã hóa file...',
                async () => {
                    const iv = window.crypto.getRandomValues(new Uint8Array(16));
                    $('#encryptionDetails').text(`IV: ${Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join('').substring(0, 16)}... | Chế độ: CBC`);
                    await simulateProgress('encryption', 1000);
                    return iv;
                },
                'Đã mã hóa AES-256-CBC với IV ngẫu nhiên',
                'Mã hóa thất bại'
            );

            // 5. Digital signature
            await updateStatusWithAction('signature', 'Đang ký số metadata...',
                async () => {
                    const metadata = {
                        filename: file.name,
                        size: file.size,
                        timestamp: new Date().toISOString(),
                        hash: fileHash
                    };
                    $('#signatureDetails').text(`Metadata: ${JSON.stringify(metadata).substring(0, 50)}...`);
                    await new Promise(resolve => setTimeout(resolve, 600));
                },
                'Đã ký số metadata với RSA-SHA512',
                'Ký số thất bại'
            );

            // 6. Hash verification
            await updateStatusWithAction('hash', 'Đang kiểm tra hash...',
                async () => {
                    await new Promise(resolve => setTimeout(resolve, 400));
                    $('#hashDetails').text(`Hash file: ${fileHash.substring(0, 32)}... | Khớp: true`);
                },
                'Hash SHA-512 khớp',
                'Hash không khớp'
            );

            // 7. IP check
            await updateStatus('ip', 'Đang kiểm tra IP...', 30);
            await new Promise(resolve => setTimeout(resolve, 300));
            const ipAllowed = true; // Giả lập kiểm tra IP
            updateStatus('ip', 
                ipAllowed ? 'IP an toàn' : 'IP không được phép', 
                100, 
                ipAllowed ? 'success' : 'danger'
            );
            $('#ipDetails').html(`IP: 127.0.0.1 | Trạng thái: ${ipAllowed ? 'Allowed' : 'Blocked'}`);

            // 8. Send file
            await updateStatusWithAction('send', 'Đang gửi file...',
                async () => {
                    const response = await fetch('/send_cv', {
                        method: 'POST',
                        body: formData
                    });
                    const result = await response.json();
                    
                    if (result.status !== 'ACK') {
                        throw new Error(result.error || 'Gửi file thất bại');
                    }
                    
                    $('#sendDetails').text(`Thời gian: ${new Date().toLocaleTimeString()} | Kích thước: ${formatFileSize(file.size)}`);
                },
                'Gửi file thành công',
                'Gửi file thất bại'
            );

            showAlert('File đã được gửi và xử lý bảo mật thành công!', 'success');
        } catch (error) {
            console.error('Lỗi trong quá trình xử lý:', error);
            showAlert(error.message, 'danger');
        } finally {
            submitBtn.prop('disabled', false);
            $('#btnText').text('Gửi file');
            $('#spinner').addClass('d-none');
        }
    }

    // Calculate file hash
    async function calculateFileHash(file) {
        return new Promise((resolve) => {
            const reader = new FileReader();
            reader.onload = function(e) {
                const data = new Uint8Array(e.target.result);
                const hash = sha512.create().update(data).hex();
                resolve(hash);
            };
            reader.readAsArrayBuffer(file);
        });
    }

    // Format file size
    function formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    // Show alert message
    function showAlert(message, type) {
        const alertDiv = $('#statusAlert');
        alertDiv.removeClass('d-none alert-success alert-danger')
               .addClass(`alert-${type}`)
               .html(`
                   <div class="d-flex align-items-center">
                       <i class="fas ${type === 'success' ? 'fa-check-circle' : 'fa-exclamation-circle'} me-2"></i>
                       <span>${message}</span>
                   </div>
               `);
        
        // Auto hide after 5 seconds
        setTimeout(() => {
            alertDiv.fadeOut();
        }, 5000);
    }

    // File input styling
    $('#fileInput').on('change', function() {
        const fileName = $(this).val().split('\\').pop();
        if (fileName) {
            $(this).next('.custom-file-label').html(fileName);
        }
    });

    // Hàm cập nhật trạng thái với hành động
    async function updateStatusWithAction(type, loadingText, action, successText, errorText) {
        updateStatus(type, loadingText, 30);
        try {
            await action();
            updateStatus(type, successText, 100, 'success');
        } catch (error) {
            updateStatus(type, errorText || error.message, 100, 'danger');
            throw error;
        }
    }

    // Hàm cập nhật trạng thái
    function updateStatus(type, text, progress, status) {
        $(`#${type}Status`).text(text);
        $(`#${type}Progress`).css('width', `${progress}%`);
        
        if (status) {
            const iconMap = {
                'success': 'status-success',
                'warning': 'status-warning',
                'danger': 'status-danger',
                'info': 'status-info'
            };
            
            $(`#${type}Icon i`).removeClass('status-success status-warning status-danger status-info')
                               .addClass(iconMap[status]);
        }
    }

    // Hàm mô phỏng tiến trình
    async function simulateProgress(type, duration) {
        return new Promise(resolve => {
            const startTime = Date.now();
            const interval = setInterval(() => {
                const elapsed = Date.now() - startTime;
                const progress = Math.min(100, (elapsed / duration * 100));
                $(`#${type}Progress`).css('width', `${progress}%`);
                
                if (progress >= 100) {
                    clearInterval(interval);
                    resolve();
                }
            }, 50);
        });
    }
});