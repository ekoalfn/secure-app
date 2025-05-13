import React, { useState, useContext, useEffect } from 'react';
import { AuthContext } from '../context/AuthContext';
import Navbar from '../components/Navbar';
import DOMPurify from 'dompurify';
import { useXSSDetection, useSecurityMonitoring, useCSRFToken } from '../security';
import SecureHtml from '../components/SecureHtml';

// TrustedHTML type
type TrustedHTML = any;

const Profile: React.FC = () => {
  const { user, updateProfile } = useContext(AuthContext);
  
  const [bio, setBio] = useState('');
  const [website, setWebsite] = useState('');
  const [message, setMessage] = useState('');
  const [loading, setLoading] = useState(false);
  const [comments, setComments] = useState<Array<{ id: number; text: string }>>([]);
  const [newComment, setNewComment] = useState('');
  const [securityWarnings, setSecurityWarnings] = useState<string[]>([]);
  
  // Enhanced security hooks
  const { checkValue: checkXSS } = useXSSDetection();
  const { logValidationFailure } = useSecurityMonitoring();
  const { getCSRFToken } = useCSRFToken();

  useEffect(() => {
    if (user) {
      setBio(user.bio || '');
      setWebsite(user.website || '');
    }
  }, [user]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setMessage('');
    setSecurityWarnings([]);
    
    // Enhanced input validation with security monitoring
    const warnings: string[] = [];
    
    // Check for XSS in bio content
    if (checkXSS(bio)) {
      warnings.push('Potential unsafe content detected in bio field');
      logValidationFailure(bio, 'bio');
    }
    
    // Validate URL format for website
    if (website && !isValidUrl(website)) {
      warnings.push('Invalid URL format in website field');
      logValidationFailure(website, 'website');
    }
    
    if (warnings.length > 0) {
      setSecurityWarnings(warnings);
      setLoading(false);
      return;
    }

    try {
      // Include CSRF token (handled automatically by our CSRF protection)
      await updateProfile({ bio, website });
      setMessage('Profile updated successfully!');
    } catch (err) {
      setMessage('Failed to update profile. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const addComment = () => {
    if (newComment.trim()) {
      // Enhanced validation and sanitization
      if (checkXSS(newComment)) {
        setSecurityWarnings(['Potentially unsafe content detected in comment']);
        logValidationFailure(newComment, 'comment');
        return;
      }
      
      const newId = comments.length > 0 ? Math.max(...comments.map(c => c.id)) + 1 : 1;
      // Securely store new comment after sanitizing input
      setComments([...comments, { id: newId, text: DOMPurify.sanitize(newComment) }]);
      setNewComment('');
      setSecurityWarnings([]);
    }
  };
  
  // URL validation helper
  const isValidUrl = (url: string): boolean => {
    try {
      const parsedUrl = new URL(url);
      return parsedUrl.protocol === 'http:' || parsedUrl.protocol === 'https:';
    } catch {
      return false;
    }
  };
  
  // Define sanitization options
  const sanitizeOptions = {
    ALLOWED_TAGS: ['p', 'br', 'b', 'i', 'em', 'strong', 'a', 'ul', 'ol', 'li'],
    ALLOWED_ATTR: ['href', 'target', 'rel'],
    FORBID_TAGS: ['script', 'style', 'iframe', 'object', 'embed', 'form', 'input'],
    FORBID_ATTR: ['onerror', 'onload', 'onclick', 'onmouseover'],
    ALLOW_DATA_ATTR: false
  };

  if (!user) {
    return <div>Loading user data...</div>;
  }

  return (
    <div className="page">
      <Navbar />
      <div className="container">
        <h1>User Profile</h1>
        
        <div className="profile-section">
          <h2>Basic Information</h2>
          <div className="profile-info">
            <p><strong>Name:</strong> {user.name}</p>
            <p><strong>Email:</strong> {user.email}</p>
          </div>
        </div>

        <div className="profile-section">
          <h2>Edit Profile</h2>
          {message && <div className="message">{message}</div>}
          {securityWarnings.length > 0 && (
            <div className="error-message">
              <strong>Security Warning:</strong>
              <ul>
                {securityWarnings.map((warning, index) => (
                  <li key={index}>{warning}</li>
                ))}
              </ul>
            </div>
          )}
          <form onSubmit={handleSubmit}>
            {/* Hidden CSRF token field */}
            <input type="hidden" name="_csrf" value={getCSRFToken()} />
            
            <div className="form-group">
              <label htmlFor="bio">Bio</label>
              <textarea
                id="bio"
                value={bio}
                onChange={(e) => {
                  const value = e.target.value;
                  setBio(value);
                  // Reset warnings when input changes
                  setSecurityWarnings([]);
                }}
                placeholder="Tell us about yourself"
              />
            </div>
            <div className="form-group">
              <label htmlFor="website">Website</label>
              <input
                type="text"
                id="website"
                value={website}
                onChange={(e) => {
                  const value = e.target.value;
                  setWebsite(value);
                  // Reset warnings when input changes
                  setSecurityWarnings([]);
                }}
                placeholder="Your website URL"
              />
            </div>
            <button type="submit" disabled={loading}>
              {loading ? 'Updating...' : 'Update Profile'}
            </button>
          </form>
        </div>

        <div className="profile-section">
          <h2>Comments</h2>
          <div className="comments-section">
            <div className="add-comment">
              <textarea
                value={newComment}
                onChange={(e) => {
                  setNewComment(e.target.value);
                  // Reset warnings when input changes
                  setSecurityWarnings([]);
                }}
                placeholder="Add a comment..."
              />
              <button onClick={addComment}>Post Comment</button>
            </div>
            
            <div className="comments-list">
              {comments.length > 0 ? (
                comments.map(comment => (
                  <div key={comment.id} className="comment">
                    {/* Using SecureHtml component instead of dangerouslySetInnerHTML */}
                    <SecureHtml 
                      content={comment.text} 
                      sanitizeOptions={sanitizeOptions}
                      className="comment-content"
                    />
                  </div>
                ))
              ) : (
                <p>No comments yet.</p>
              )}
            </div>
          </div>
        </div>

        <div className="profile-section">
          <h2>Bio Preview</h2>
          {/* Using SecureHtml component instead of dangerouslySetInnerHTML */}
          <SecureHtml 
            content={bio} 
            sanitizeOptions={sanitizeOptions}
            className="bio-preview" 
          />
        </div>
      </div>
    </div>
  );
};

export default Profile; 