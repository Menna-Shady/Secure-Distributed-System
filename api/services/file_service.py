def save_uploaded_file(cur, user_id, filename, path, file_hash, signature):
    cur.execute("""
        INSERT INTO uploaded_files (user_id, filename, path, file_hash,signature)
        VALUES (%s, %s, %s, %s, %s)
    """, (user_id, filename, path, file_hash, signature))
    
    