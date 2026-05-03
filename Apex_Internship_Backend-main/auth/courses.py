from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import logging

from . import utils
from .models import TokenData
from .supabase_client import supabase

logger = logging.getLogger(__name__)
router = APIRouter(tags=["courses"])

# --- MODELS ---
class CourseAccessRequest(BaseModel):
    course_id: str
    track_id: Optional[str] = None

class CourseResponse(BaseModel):
    id: str
    title: str
    description: str
    thumbnail_url: Optional[str] = None
    duration: Optional[int] = None
    difficulty: Optional[str] = None
    is_locked: bool = False
    upgrade_required: bool = False

# --- DEPENDENCIES ---
async def get_current_user():
    """Import the dependency from auth routes"""
    from .routes import get_current_user as auth_get_current_user
    return await auth_get_current_user()

# --- ACCESS CONTROL HELPERS ---
async def check_course_access(user_wallet: str, course_id: str, track_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Check if user has access to a specific course.
    Returns dict with: {has_access: bool, upgrade_required: bool, reason: str}
    """
    try:
        # Check if user is enrolled in any tracks
        enrollment_result = supabase.from_("enrollments")\
            .select("track_id, status, access_level")\
            .eq("wallet_address", user_wallet.lower())\
            .eq("status", "active")\
            .execute()
        
        if not enrollment_result.data:
            return {
                "has_access": False,
                "upgrade_required": True,
                "reason": "No active enrollment found"
            }
        
        # Check if course is part of enrolled tracks
        if track_id:
            track_access = supabase.from_("track_courses")\
                .select("course_id")\
                .eq("track_id", track_id)\
                .eq("course_id", course_id)\
                .execute()
            
            if not track_access.data:
                return {
                    "has_access": False,
                    "upgrade_required": True,
                    "reason": "Course not part of enrolled track"
                }
        
        # Check specific course access permissions
        course_access = supabase.from_("course_access")\
            .select("access_level, requires_upgrade")\
            .eq("course_id", course_id)\
            .execute()
        
        if course_access.data:
            access_info = course_access.data[0]
            user_access_level = enrollment_result.data[0].get("access_level", "basic")
            
            if access_info.get("requires_upgrade", False) and user_access_level != "premium":
                return {
                    "has_access": False,
                    "upgrade_required": True,
                    "reason": "Premium access required"
                }
        
        return {
            "has_access": True,
            "upgrade_required": False,
            "reason": "Access granted"
        }
        
    except Exception as e:
        logger.error(f"Error checking course access: {e}")
        return {
            "has_access": False,
            "upgrade_required": True,
            "reason": "Access check failed"
        }

# --- ROUTES ---
@router.get("/courses/{course_id}/access")
async def get_course_access(
    course_id: str,
    track_id: Optional[str] = None,
    current_user: TokenData = Depends(get_current_user)
):
    """
    Check if user has access to a specific course.
    """
    access_result = await check_course_access(
        current_user.wallet_address, 
        course_id, 
        track_id
    )
    
    if not access_result["has_access"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "Access Denied",
                "upgrade_required": access_result["upgrade_required"],
                "reason": access_result["reason"]
            }
        )
    
    return {"access": "granted", "course_id": course_id}

@router.get("/courses")
async def get_courses(
    track_id: Optional[str] = None
):
    """
    Get all courses with access status for the current user.
    """
    try:
        # Mock courses data for development
        mock_courses = [
            {
                "id": "course-1",
                "title": "Introduction to Web Security",
                "description": "Learn the fundamentals of web application security",
                "thumbnail_url": None,
                "duration": "4 hours",
                "difficulty": "Beginner",
                "is_locked": False,
                "upgrade_required": False
            },
            {
                "id": "course-2", 
                "title": "Advanced Authentication",
                "description": "Master modern authentication techniques",
                "thumbnail_url": None,
                "duration": "6 hours",
                "difficulty": "Advanced",
                "is_locked": False,
                "upgrade_required": False
            },
            {
                "id": "course-3",
                "title": "Security Testing Tools",
                "description": "Learn to use industry-standard security testing tools",
                "thumbnail_url": None,
                "duration": "8 hours",
                "difficulty": "Intermediate",
                "is_locked": True,
                "upgrade_required": True
            }
        ]
        
        return mock_courses
        
    except Exception as e:
        logger.error(f"Error fetching courses: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch progress")

@router.get("/leaderboard")
async def get_leaderboard(
    page: int = 1,
    limit: int = 10,
    search: Optional[str] = None
):
    """
    Get leaderboard data with pagination and search.
    """
    try:
        # Mock leaderboard data for development
        mock_leaderboard = [
            {
                "rank": 1,
                "wallet_address": "0x1234...5678",
                "display_name": "Alice Developer",
                "total_points": 3250,
                "completed_courses": 8,
                "current_streak": 15,
                "badges": ["Early Adopter", "Quick Learner", "Perfect Score"],
                "avatar_url": None,
                "last_active": "2025-02-20T10:30:00Z"
            },
            {
                "rank": 2,
                "wallet_address": "0x8765...4321",
                "display_name": "Bob Security",
                "total_points": 2890,
                "completed_courses": 6,
                "current_streak": 12,
                "badges": ["Consistent Learner", "Security Expert"],
                "avatar_url": None,
                "last_active": "2025-02-19T15:45:00Z"
            },
            {
                "rank": 3,
                "wallet_address": "0x9876...1234",
                "display_name": "Charlie Tester",
                "total_points": 2450,
                "completed_courses": 5,
                "current_streak": 8,
                "badges": ["Bug Hunter", "Team Player"],
                "avatar_url": None,
                "last_active": "2025-02-18T09:20:00Z"
            },
            {
                "rank": 4,
                "wallet_address": "0x5432...8765",
                "display_name": "Diana Analyst",
                "total_points": 2100,
                "completed_courses": 4,
                "current_streak": 6,
                "badges": ["Detail Oriented"],
                "avatar_url": None,
                "last_active": "2025-02-17T14:15:00Z"
            },
            {
                "rank": 5,
                "wallet_address": "0x2468...1357",
                "display_name": "Eve Engineer",
                "total_points": 1890,
                "completed_courses": 3,
                "current_streak": 4,
                "badges": ["Problem Solver"],
                "avatar_url": None,
                "last_active": "2025-02-16T11:30:00Z"
            }
        ]
        
        # Apply search filter if provided
        if search:
            search_lower = search.lower()
            mock_leaderboard = [
                user for user in mock_leaderboard
                if search_lower in user['display_name'].lower() or 
                   search_lower in user['wallet_address'].lower()
            ]
        
        # Apply pagination
        start_index = (page - 1) * limit
        end_index = start_index + limit
        paginated_data = mock_leaderboard[start_index:end_index]
        
        return {
            "participants": paginated_data,
            "current_user": {
                "rank": 12,
                "wallet_address": "0xcurrent...user",
                "display_name": "You",
                "total_points": 1450,
                "completed_courses": 3,
                "current_streak": 4,
                "badges": ["Active Learner"],
                "avatar_url": None,
                "last_active": "2025-02-20T08:30:00Z"
            },
            "total_count": len(mock_leaderboard)
        }
        
    except Exception as e:
        logger.error(f"Error fetching leaderboard: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch leaderboard")

@router.get("/profile")
async def get_user_profile():
    """
    Get user profile information.
    """
    try:
        # Mock profile data for development
        mock_profile = {
            "first_name": "John",
            "last_name": "Developer",
            "email": "john.developer@example.com",
            "phone": "+1-555-0123-4567",
            "bio": "Passionate about web security and blockchain development. Always learning and exploring new technologies.",
            "location": "San Francisco, CA",
            "role": "Student",
            "track": "Web Security Fundamentals",
            "join_date": "2025-01-15T00:00:00Z",
            "avatar_url": None,
            "wallet_address": "0x1234567890123456789012345678901234"
        }
        
        return mock_profile
        
    except Exception as e:
        logger.error(f"Error fetching profile: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch profile")

@router.get("/profile/stats")
async def get_user_profile_stats():
    """
    Get user profile statistics.
    """
    try:
        # Mock profile stats for development
        mock_stats = {
            "completed_courses": 8,
            "points_earned": 3250,
            "certifications": 3,
            "overall_progress": 65,
            "current_streak": 15,
            "total_learning_hours": 120,
            "skills_mastered": 12,
            "badges_earned": 7
        }
        
        return mock_stats
        
    except Exception as e:
        logger.error(f"Error fetching profile stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch profile stats")

@router.get("/profile/skills")
async def get_user_profile_skills():
    """
    Get user profile skills.
    """
    try:
        # Mock skills data for development
        mock_skills = [
            {
                "id": "skill-1",
                "name": "JavaScript",
                "level": "Advanced",
                "category": "Programming",
                "earned_date": "2025-01-20T00:00:00Z",
                "projects_completed": 5
            },
            {
                "id": "skill-2",
                "name": "React",
                "level": "Intermediate",
                "category": "Frontend",
                "earned_date": "2025-02-01T00:00:00Z",
                "projects_completed": 3
            },
            {
                "id": "skill-3",
                "name": "Node.js",
                "level": "Intermediate",
                "category": "Backend",
                "earned_date": "2025-02-10T00:00:00Z",
                "projects_completed": 4
            },
            {
                "id": "skill-4",
                "name": "Security Testing",
                "level": "Advanced",
                "category": "Security",
                "earned_date": "2025-02-15T00:00:00Z",
                "projects_completed": 6
            }
        ]
        
        return mock_skills
        
    except Exception as e:
        logger.error(f"Error fetching profile skills: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch profile skills")

@router.get("/settings/account")
async def get_account_settings():
    """
    Get user account settings.
    """
    try:
        # Mock account settings for development
        mock_settings = {
            "email": "john.developer@example.com",
            "notifications": {
                "email_notifications": True,
                "push_notifications": True,
                "course_updates": True,
                "achievement_alerts": True,
                "weekly_progress": True,
                "marketing_emails": False
            },
            "privacy": {
                "profile_visibility": "public",
                "show_progress": True,
                "show_certificates": True,
                "allow_messages": True
            },
            "security": {
                "two_factor_enabled": False,
                "session_timeout": 24,
                "login_alerts": True
            },
            "preferences": {
                "theme": "light",
                "language": "en",
                "timezone": "UTC-8",
                "auto_play_videos": False
            }
        }
        
        return mock_settings
        
    except Exception as e:
        logger.error(f"Error fetching account settings: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch account settings")

@router.put("/settings/account")
async def update_account_settings(settings_data: dict):
    """
    Update user account settings.
    """
    try:
        # Mock update functionality for development
        # In a real implementation, this would update the database
        updated_settings = {
            "message": "Settings updated successfully",
            "updated_fields": list(settings_data.keys()),
            "timestamp": "2025-02-22T06:25:00Z"
        }
        
        return updated_settings
        
    except Exception as e:
        logger.error(f"Error updating account settings: {e}")
        raise HTTPException(status_code=500, detail="Failed to update account settings")

@router.get("/billing/subscription")
async def get_billing_subscription():
    """
    Get user billing subscription information.
    """
    try:
        # Mock subscription data for development
        mock_subscription = {
            "plan": {
                "id": "pro-monthly",
                "name": "Pro Plan",
                "price": 29.99,
                "billing_cycle": "monthly",
                "features": [
                    "Unlimited course access",
                    "Advanced security labs",
                    "Priority support",
                    "Certificate verification",
                    "Download resources"
                ],
                "status": "active"
            },
            "current_period": {
                "start_date": "2025-01-15T00:00:00Z",
                "end_date": "2025-02-15T00:00:00Z",
                "days_remaining": 7
            },
            "payment_method": {
                "type": "credit_card",
                "last_four": "1234",
                "brand": "visa",
                "expires_month": 12,
                "expires_year": 2025
            },
            "usage": {
                "courses_accessed": 12,
                "lab_hours_used": 45,
                "downloads_count": 8
            }
        }
        
        return mock_subscription
        
    except Exception as e:
        logger.error(f"Error fetching billing subscription: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch billing subscription")

@router.get("/billing/invoices")
async def get_billing_invoices():
    """
    Get user billing invoices.
    """
    try:
        # Mock invoice data for development
        mock_invoices = [
            {
                "id": "inv-001",
                "date": "2025-02-15T00:00:00Z",
                "amount": 29.99,
                "status": "paid",
                "description": "Pro Plan - Monthly Subscription",
                "payment_method": "Visa ending in 1234",
                "download_url": "https://example.com/invoices/inv-001.pdf"
            },
            {
                "id": "inv-002", 
                "date": "2025-01-15T00:00:00Z",
                "amount": 29.99,
                "status": "paid",
                "description": "Pro Plan - Monthly Subscription",
                "payment_method": "Visa ending in 1234",
                "download_url": "https://example.com/invoices/inv-002.pdf"
            },
            {
                "id": "inv-003",
                "date": "2024-12-15T00:00:00Z", 
                "amount": 29.99,
                "status": "paid",
                "description": "Pro Plan - Monthly Subscription",
                "payment_method": "Visa ending in 1234",
                "download_url": "https://example.com/invoices/inv-003.pdf"
            }
        ]
        
        return mock_invoices
        
    except Exception as e:
        logger.error(f"Error fetching billing invoices: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch billing invoices")

@router.get("/billing/payment-methods")
async def get_billing_payment_methods():
    """
    Get user billing payment methods.
    """
    try:
        # Mock payment methods data for development
        mock_payment_methods = [
            {
                "id": "pm-001",
                "type": "credit_card",
                "brand": "visa",
                "last_four": "1234",
                "expires_month": 12,
                "expires_year": 2025,
                "is_default": True,
                "added_date": "2024-01-15T00:00:00Z"
            },
            {
                "id": "pm-002",
                "type": "credit_card", 
                "brand": "mastercard",
                "last_four": "5678",
                "expires_month": 8,
                "expires_year": 2025,
                "is_default": False,
                "added_date": "2023-06-20T00:00:00Z"
            }
        ]
        
        return mock_payment_methods
        
    except Exception as e:
        logger.error(f"Error fetching payment methods: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch payment methods")

@router.get("/enrollments")
async def get_user_enrollments():
    """
    Get user's course enrollments with progress.
    """
    try:
        # Mock enrollment data for development
        mock_enrollments = [
            {
                "id": "track-1",
                "title": "Web Security Fundamentals",
                "description": "Learn the basics of web security",
                "thumbnail_url": None,
                "progress": 75,
                "total_lessons": 12,
                "completed_lessons": 9,
                "last_accessed": "2025-02-20T10:30:00Z",
                "status": "in_progress"
            },
            {
                "id": "track-2", 
                "title": "Advanced Penetration Testing",
                "description": "Master advanced penetration testing techniques",
                "thumbnail_url": None,
                "progress": 30,
                "total_lessons": 20,
                "completed_lessons": 6,
                "last_accessed": "2025-02-18T15:45:00Z",
                "status": "in_progress"
            }
        ]
        
        return mock_enrollments
        
    except Exception as e:
        logger.error(f"Error fetching enrollments: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch enrollments")

@router.get("/progress")
async def get_user_progress():
    """
    Get user's overall progress data.
    """
    try:
        # Mock progress data for development
        mock_progress = {
            "overall_progress": 65,
            "total_points": 2450,
            "completed_courses": 3,
            "total_courses": 5,
            "current_streak": 7,
            "skills_earned": ["JavaScript", "React", "Node.js", "Security Testing"],
            "achievements": [
                {"id": "first-course", "name": "Course Completed", "earned_date": "2025-02-15"},
                {"id": "week-streak", "name": "7 Day Streak", "earned_date": "2025-02-20"}
            ]
        }
        
        return mock_progress
        
    except Exception as e:
        logger.error(f"Error fetching progress: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch progress")

@router.get("/courses/{course_id}")
async def get_course_details(
    course_id: str,
    track_id: Optional[str] = None,
    current_user: TokenData = Depends(get_current_user)
):
    """
    Get detailed course information if user has access.
    """
    access_result = await check_course_access(
        current_user.wallet_address,
        course_id,
        track_id
    )
    
    if not access_result["has_access"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "Access Denied",
                "upgrade_required": access_result["upgrade_required"],
                "reason": access_result["reason"]
            }
        )
    
    # Get course details
    course_result = supabase.from_("courses")\
        .select("*")\
        .eq("id", course_id)\
        .execute()
    
    if not course_result.data:
        raise HTTPException(status_code=404, detail="Course not found")
    
    course = course_result.data[0]
    
    # Get course lessons if user has access
    lessons_result = supabase.from_("lessons")\
        .select("*")\
        .eq("course_id", course_id)\
        .order("order")\
        .execute()
    
    return {
        "course": course,
        "lessons": lessons_result.data or [],
        "access": "granted"
    }
