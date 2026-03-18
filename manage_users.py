#!/usr/bin/env python
"""
User creation management script for FenrisHub.
Run this script to create new defender users.
"""

import os
import sys
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'fenrishub.settings')
django.setup()

from django.contrib.auth.models import User
import getpass


def create_user():
    """Interactive user creation."""
    print("\n" + "="*50)
    print("FenrisHub - User Creation")
    print("="*50 + "\n")
    
    while True:
        username = input("Enter username: ").strip()
        
        if not username:
            print("Username cannot be empty.")
            continue
        
        if User.objects.filter(username=username).exists():
            print(f"Error: User '{username}' already exists.")
            continue
        
        break
    
    while True:
        password = getpass.getpass("Enter password: ")
        password_confirm = getpass.getpass("Confirm password: ")
        
        if password != password_confirm:
            print("Passwords do not match. Try again.")
            continue
        
        if len(password) < 6:
            print("Password should be at least 6 characters long.")
            continue
        
        break
    
    try:
        user = User.objects.create_user(username=username, password=password)
        print(f"\n✓ User '{username}' created successfully!")
        print(f"User ID: {user.id}")
    except Exception as e:
        print(f"\n✗ Error creating user: {e}")
        return
    
    # Ask if user should be staff
    is_staff = input("\nMake this user a staff member (can access admin)? (y/n): ").lower().strip()
    if is_staff == 'y':
        user.is_staff = True
        user.save()
        print("User is now a staff member.")
    
    print("\n" + "="*50)


def list_users():
    """List all users."""
    print("\n" + "="*50)
    print("FenrisHub - User List")
    print("="*50 + "\n")
    
    users = User.objects.all()
    
    if not users.exists():
        print("No users found.")
        return
    
    print(f"{'Username':<20} {'Staff':<10} {'Active':<10} {'Joined':<20}")
    print("-" * 60)
    
    for user in users:
        print(f"{user.username:<20} {str(user.is_staff):<10} {str(user.is_active):<10} {user.date_joined.strftime('%Y-%m-%d %H:%M'):<20}")
    
    print("\n" + "="*50)


def delete_user():
    """Delete a user."""
    print("\n" + "="*50)
    print("FenrisHub - Delete User")
    print("="*50 + "\n")
    
    username = input("Enter username to delete: ").strip()
    
    try:
        user = User.objects.get(username=username)
        confirm = input(f"Are you sure you want to delete '{username}'? (yes/no): ").lower().strip()
        
        if confirm == 'yes':
            user.delete()
            print(f"✓ User '{username}' deleted successfully!")
        else:
            print("Deletion cancelled.")
    except User.DoesNotExist:
        print(f"Error: User '{username}' not found.")


def main():
    """Main menu."""
    while True:
        print("\n" + "="*50)
        print("FenrisHub - User Management")
        print("="*50)
        print("1. Create new user")
        print("2. List all users")
        print("3. Delete user")
        print("4. Exit")
        print("="*50)
        
        choice = input("\nSelect an option (1-4): ").strip()
        
        if choice == '1':
            create_user()
        elif choice == '2':
            list_users()
        elif choice == '3':
            delete_user()
        elif choice == '4':
            print("\nGoodbye!")
            break
        else:
            print("Invalid option. Please try again.")


if __name__ == '__main__':
    main()
